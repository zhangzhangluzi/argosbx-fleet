"""Linux CI only: queued datagrams, fresh sockets, and rollback with real pidfd."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import udp_buffers as buffers

CHILD = r'''
import json,os,socket,sys
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
udp.bind(('127.0.0.1',0));udp.settimeout(2)
udp6=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
udp6.bind(('::1',0))
tcp=socket.socket();tcp.bind(('127.0.0.1',0));tcp.listen()
print(json.dumps({'pid':os.getpid(),'port':udp.getsockname()[1]}),flush=True)
new=[]
for line in sys.stdin:
 cmd=line.strip()
 if cmd=='receive':
  data,addr=udp.recvfrom(4096);udp.sendto(data,addr)
  print(json.dumps({'echo':len(data)}),flush=True)
 elif cmd=='new':
  sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));new.append(sock)
  print(json.dumps({'receive':sock.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)}),flush=True)
 elif cmd=='state':
  print(json.dumps({'receive':udp.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF),
                   'receive6':udp6.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF),
                   'send':udp.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF)}),flush=True)
 elif cmd=='drain':
  count=0;udp.settimeout(.05)
  try:
   while True:udp.recvfrom(4096);count+=1
  except TimeoutError:pass
  udp.settimeout(2);print(json.dumps({'received':count}),flush=True)
'''

if __name__ == '__main__':
    assert sys.platform == 'linux' and os.geteuid() == 0
    original = buffers.SYSCTL.read_text()
    old_max = buffers.LIMIT.read_text()
    process = None
    try:
        buffers.SYSCTL.write_text('212992\n')
        buffers.LIMIT.write_text(str(max(int(old_max), 2097152)))
        with tempfile.TemporaryDirectory(prefix='udp-buffer-native-') as temp:
            root = Path(temp)
            process = subprocess.Popen([sys.executable, '-u', '-c', CHILD],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            address = json.loads(process.stdout.readline())
            owner = buffers.identity(address['pid'])
            def command(value):
                process.stdin.write(value + '\n');process.stdin.flush()
                return json.loads(process.stdout.readline())
            with patch.object(buffers, 'service', return_value=owner), \
                 patch.object(buffers, 'PERSIST', root / 'sysctl.conf'), \
                 patch.object(buffers, 'JOURNAL', root / 'journal.json'), \
                 patch.object(buffers, 'RECEIPT', root / 'receipt.json'), \
                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                before = command('state')
                def burst():
                    for _ in range(256):
                        client.sendto(b'x'*1200, ('127.0.0.1', address['port']))
                    return command('drain')['received']
                small_burst = burst()
                queued = b'queued-before-buffer-change'
                client.sendto(queued, ('127.0.0.1', address['port']))
                result = buffers.apply(unit='argosbx-reality443')
                assert json.loads(buffers.RECEIPT.read_text())['unit'] == 'argosbx-reality443'
                assert len(result['adjusted']) == 2, 'only IPv4/IPv6 UDP descriptors should change'
                assert command('receive')['echo'] == len(queued)
                assert client.recvfrom(4096)[0] == queued
                state = command('state')
                assert state == {'receive': 2097152, 'receive6': 2097152, 'send': before['send']}
                large_burst = burst()
                assert small_burst < large_burst == 256
                assert command('new')['receive'] == 2097152
                assert not buffers.apply(unit='argosbx-reality443')['changed']
                buffers.recover()
                assert command('state') == before
                assert command('new')['receive'] == 212992
                client.sendto(b'after-rollback', ('127.0.0.1', address['port']))
                assert command('receive')['echo'] == 14
                assert client.recvfrom(4096)[0] == b'after-rollback'
                assert buffers.identity(process.pid) == owner
            print(json.dumps({'existing_datagram_preserved': True, 'new_socket_inherits': True,
                              'tcp_untouched': True, 'rollback_verified': True, 'pid_unchanged': True,
                              'burst_sent': 256, 'small_buffer_received': small_burst,
                              'large_buffer_received': large_burst}))
    finally:
        if process is not None:
            process.terminate();process.wait(timeout=5)
        buffers.SYSCTL.write_text(original)
        buffers.LIMIT.write_text(old_max)
