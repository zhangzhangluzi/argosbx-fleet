"""Linux UDP defaults for new hosts and opt-in live tuning; no service restart."""
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


def persistent_body(target, maximum=None):
    body = '# Managed by ArgoSBX Fleet; effective bytes for new default sockets.\n'
    if maximum is not None:
        body += 'net.core.rmem_max = %d\n' % maximum
    return body + 'net.core.rmem_default = %d\n' % target


def verify_defaults(minimum=DEFAULT_BYTES):
    actual, maximum = int(SYSCTL.read_text()), int(LIMIT.read_text())
    saved = snapshot_file()
    values = {}
    for line in (saved or {}).get('text', '').splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            key, _, value = line.partition('=')
            values[key.strip()] = int(value.strip())
    if (actual < minimum or maximum < actual or fresh_default() != actual
            or values.get('net.core.rmem_default', 0) < minimum
            or values.get('net.core.rmem_max', 0) < values.get('net.core.rmem_default', 0)):
        raise RuntimeError('initialized UDP defaults or persistence did not verify')
    return {'verified': True, 'effective_receive': actual, 'maximum': maximum,
            'persistent': str(PERSIST)}


def initialize_defaults():
    """Called before new-host services start; does not require a live process."""
    if JOURNAL.exists():
        raise RuntimeError('unfinished UDP buffer transaction; run recover')
    old_default, old_max = int(SYSCTL.read_text()), int(LIMIT.read_text())
    target = max(DEFAULT_BYTES, old_default)
    maximum = max(old_max, target)
    before_file = snapshot_file()
    body = persistent_body(target, maximum)
    if old_default == target and old_max == maximum and before_file and before_file['text'] == body:
        return {'changed': False, **verify_defaults()}
    record = {'kind': 'defaults', 'default_before': old_default, 'maximum_before': old_max,
              'maximum_after': maximum, 'target': target, 'file_before': before_file,
              'file_after': body}
    save(JOURNAL, record)
    try:
        LIMIT.write_text(str(maximum) + '\n')
        SYSCTL.write_text(str(target) + '\n')
        atomic(PERSIST, body, 0o644)
        result = verify_defaults()
        save(RECEIPT, record)
        JOURNAL.unlink()
        return {'changed': True, **result}
    except Exception:
        try:
            SYSCTL.write_text(str(old_default) + '\n')
            LIMIT.write_text(str(old_max) + '\n')
            restore_file(before_file)
            if (int(SYSCTL.read_text()) != old_default or int(LIMIT.read_text()) != old_max
                    or fresh_default() != old_default or snapshot_file() != before_file):
                raise RuntimeError('initialization rollback readback failed')
        except Exception:
            raise RuntimeError('initialization rollback incomplete; run recover')
        JOURNAL.unlink(missing_ok=True)
        raise


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
    # Keep the new-host maximum persistent when later tuning existing sockets.
    managed_max = before_file and any(line.strip().startswith('net.core.rmem_max')
                                     for line in before_file['text'].splitlines())
    body = persistent_body(target, int(LIMIT.read_text()) if managed_max else None)
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
    if record.get('kind') == 'defaults':
        if int(LIMIT.read_text()) not in (record['maximum_before'], record['maximum_after']):
            raise RuntimeError('receive maximum changed externally; refusing to overwrite')
        SYSCTL.write_text(str(record['default_before']) + '\n')
        LIMIT.write_text(str(record['maximum_before']) + '\n')
        restore_file(record['file_before'])
        if (fresh_default() != record['default_before']
                or int(LIMIT.read_text()) != record['maximum_before']
                or snapshot_file() != record['file_before']):
            raise RuntimeError('defaults recovery readback failed')
        JOURNAL.unlink(missing_ok=True)
        RECEIPT.unlink(missing_ok=True)
        return {'recovered': True, 'default': record['default_before'],
                'maximum': record['maximum_before'], 'existing_sockets_unchanged': True}
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
