"""Opt-in Linux receive-buffer tuning; no restart, socket I/O, or daemon."""
import argparse
import contextlib
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import socket
import subprocess

from storage import atomic, lock, save

DEFAULT_BYTES = 2 * 1024 * 1024
SYSCTL = Path('/proc/sys/net/core/rmem_default')
LIMIT = Path('/proc/sys/net/core/rmem_max')
PERSIST = Path('/etc/sysctl.d/99-zz-argosbx-udp-buffers.conf')
HOME = Path('/etc/argosbx-fleet')
JOURNAL = HOME / 'udp-buffers-journal.json'
RECEIPT = HOME / 'udp-buffers-receipt.json'


def identity(pid):
    # comm may contain spaces and parentheses.
    return {'pid': pid, 'start': Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19],
            'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def service():
    pid = int(subprocess.check_output(
        ['systemctl', 'show', 'sb', '-p', 'MainPID', '--value'], text=True).strip())
    if pid <= 1 or Path(f'/proc/{pid}/exe').resolve() != Path('/root/agsbx/sing-box').resolve():
        raise RuntimeError('sb is not the expected running sing-box')
    return identity(pid)


def duplicate(pidfd, fd):
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'aarch64'):
        raise RuntimeError('pidfd_getfd requires supported Linux x86_64/aarch64')
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(438, pidfd, fd, 0)
    if result < 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))
    return result


@contextlib.contextmanager
def udp_sockets(pid):
    """Hold duplicates only for this transaction; never consume queued packets."""
    held = []
    pidfd = os.pidfd_open(pid)
    try:
        for path in sorted(Path(f'/proc/{pid}/fd').iterdir(), key=lambda p: int(p.name)):
            try:
                link = os.readlink(path)
                if not link.startswith('socket:['):
                    continue
                inode = int(link[8:-1])
                fd = duplicate(pidfd, int(path.name))
            except OSError as error:
                if error.errno in (errno.ENOENT, errno.EBADF):
                    continue  # A socket closed during enumeration.
                raise
            try:
                if os.fstat(fd).st_ino != inode:
                    os.close(fd)
                    continue  # The original FD number was reused.
                sock = socket.socket(fileno=fd)
            except Exception:
                # socket.socket closes an invalid socket FD on some platforms.
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            if sock.family not in (socket.AF_INET, socket.AF_INET6) or sock.type != socket.SOCK_DGRAM:
                sock.close()
                continue
            held.append((sock, {'fd': int(path.name), 'inode': inode,
                                'family': int(sock.family), 'port': sock.getsockname()[1],
                                'receive': sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                                'send': sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)}))
        yield held
    finally:
        for sock, _ in held:
            sock.close()
        os.close(pidfd)


def set_receive(sock, effective_bytes):
    # Linux doubles SO_RCVBUF requests; sysctl rmem_default is already effective.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, effective_bytes // 2)
    actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    if actual != effective_bytes:
        raise RuntimeError(f'kernel receive-buffer readback differs: {actual}')


def snapshot_file():
    if PERSIST.is_symlink():
        raise RuntimeError('refusing symlink for owned sysctl file')
    return {'text': PERSIST.read_text(), 'mode': PERSIST.stat().st_mode & 0o777} if PERSIST.exists() else None


def restore_file(before):
    if before is None:
        PERSIST.unlink(missing_ok=True)
    else:
        atomic(PERSIST, before['text'], before['mode'])


def fresh_default():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        return sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)


def apply(target=DEFAULT_BYTES):
    if type(target) is not int or target < 65536 or target > int(LIMIT.read_text()) or target % 2:
        raise ValueError('effective bytes must be even, >= 65536 and <= rmem_max')
    if JOURNAL.exists():
        raise RuntimeError('unfinished UDP buffer transaction; run recover')
    owner = service()
    before_default = int(SYSCTL.read_text())
    if before_default > target:
        raise RuntimeError('refusing to lower the existing default')
    before_file = snapshot_file()
    body = '# Managed by ArgoSBX Fleet; effective bytes for new default sockets.\nnet.core.rmem_default = %d\n' % target
    with udp_sockets(owner['pid']) as held:
        if not held:
            raise RuntimeError('no INET UDP sockets found; nothing changed')
        if service() != owner:
            raise RuntimeError('sb process changed before apply')
        changed = [(sock, data) for sock, data in held if data['receive'] < target]
        if not changed and before_default == target and before_file and before_file['text'] == body:
            return {'changed': False, 'owner': owner, 'sockets': [data for _, data in held]}
        record = {'owner': owner, 'default_before': before_default, 'file_before': before_file,
                  'target': target, 'file_after': body, 'sockets': [data for _, data in changed]}
        save(JOURNAL, record)
        try:
            # New sockets created after this point inherit the target automatically.
            SYSCTL.write_text(str(target) + '\n')
            if int(SYSCTL.read_text()) != target or fresh_default() != target:
                raise RuntimeError('new socket did not inherit the requested default')
            for sock, _ in changed:
                set_receive(sock, target)
            # Also capture sockets born between the first scan and the sysctl write.
            with udp_sockets(owner['pid']) as current:
                extra = [(s, d) for s, d in current if d['receive'] < target]
                # Keep duplicate handles until rollback/commit completes.
                held.extend((socket.socket(fileno=os.dup(s.fileno())), d) for s, d in extra)
                changed.extend(held[-len(extra):] if extra else [])
                record['sockets'] = [data for _, data in changed]
                save(JOURNAL, record)
                for sock, _ in extra:
                    set_receive(sock, target)
            atomic(PERSIST, body, 0o644)
            if service() != owner:
                raise RuntimeError('sb process changed during apply')
            with udp_sockets(owner['pid']) as current:
                result = [data for _, data in current]
                if any(data['receive'] < target for data in result):
                    raise RuntimeError('a UDP socket did not retain the receive buffer')
            save(RECEIPT, record)
            JOURNAL.unlink()
            return {'changed': True, 'owner': owner, 'default_before': before_default,
                    'default_after': target, 'adjusted': record['sockets'], 'sockets': result,
                    'persistent': str(PERSIST), 'fresh_socket_receive': fresh_default()}
        except Exception:
            # Handles pin the original sockets even if the process closed/reused its FD.
            errors = []
            for sock, data in changed:
                try:
                    set_receive(sock, data['receive'])
                except Exception as error:
                    errors.append(type(error).__name__)
            try:
                SYSCTL.write_text(str(before_default) + '\n')
                restore_file(before_file)
                if int(SYSCTL.read_text()) != before_default or snapshot_file() != before_file:
                    raise RuntimeError('rollback readback failed')
            except Exception as error:
                errors.append(type(error).__name__)
            if not errors:
                JOURNAL.unlink(missing_ok=True)
            else:
                raise RuntimeError('rollback incomplete; transaction retained for recover')
            raise


def recover():
    source = JOURNAL if JOURNAL.exists() else RECEIPT
    record = json.loads(source.read_text())
    current_file = snapshot_file()
    if current_file not in (record['file_before'], {'text': record['file_after'], 'mode': 0o644}):
        raise RuntimeError('sysctl file changed externally; refusing to overwrite')
    if int(SYSCTL.read_text()) not in (record['default_before'], record['target']):
        raise RuntimeError('receive default changed externally; refusing to overwrite')
    restored = 0
    # A restarted process must not be confused with the original PID.
    try:
        owner = service()
    except (RuntimeError, FileNotFoundError, subprocess.CalledProcessError):
        owner = None  # A stopped service still permits restoring the system default.
    if owner == record['owner']:
        wanted = {d['inode']: d for d in record['sockets']}
        with udp_sockets(record['owner']['pid']) as held:
            for sock, data in held:
                if data['inode'] in wanted:
                    original = wanted[data['inode']]['receive']
                    if data['receive'] not in (original, record['target']):
                        raise RuntimeError('socket buffer changed externally; refusing to overwrite')
            for sock, data in held:
                if data['inode'] in wanted:
                    set_receive(sock, wanted[data['inode']]['receive'])
                    restored += 1
    SYSCTL.write_text(str(record['default_before']) + '\n')
    restore_file(record['file_before'])
    if fresh_default() != record['default_before'] or snapshot_file() != record['file_before']:
        raise RuntimeError('recovery readback failed')
    JOURNAL.unlink(missing_ok=True)
    RECEIPT.unlink(missing_ok=True)
    return {'recovered': True, 'restored_original_sockets': restored,
            'default': record['default_before'], 'newer_sockets_retained_until_close': True}


def inspect():
    owner = service()
    with udp_sockets(owner['pid']) as held:
        return {'owner': owner, 'default': int(SYSCTL.read_text()), 'maximum': int(LIMIT.read_text()),
                'persistent': snapshot_file(), 'sockets': [data for _, data in held]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect', 'apply', 'recover'])
    parser.add_argument('--effective-bytes', type=int, default=DEFAULT_BYTES)
    args = parser.parse_args()
    with lock(HOME / 'udp-buffers.lock'):
        result = apply(args.effective_bytes) if args.action == 'apply' else globals()[args.action]()
    print(json.dumps(result))
