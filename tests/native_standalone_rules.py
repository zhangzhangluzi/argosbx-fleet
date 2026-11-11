"""Isolated acceptance against the installed FlClash core; no TUN or ports."""
import copy
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_standalone_rules import apply

raw = json.loads(Path(sys.argv[1]).read_text())
stash = yaml.safe_load(raw['stash'])
assert len(stash['rules']) > 100 and len(stash['rule-providers']) == 3
assert 'proxies' not in stash and 'dns' not in stash
assert not any(r.startswith(('MATCH,','DST-PORT,53,','DST-PORT,853,')) for r in stash['rules'])
assert any(r.startswith('DOMAIN,ads.applovin.com,') for r in stash['rules'])
assert not any(x in raw['stash'] for x in ('never-export', 'password:'))

base = {'mixed-port':0,'port':0,'socks-port':0,'allow-lan':False,
        'bind-address':'127.0.0.1','tun':{'enable':False},'dns':{'enable':False},
        'geo-auto-update':False,'find-process-mode':'off','log-level':'error',
        'proxies':[{'name':'fake-one','type':'socks5','server':'127.0.0.1','port':9},
                   {'name':'fake-two','type':'socks5','server':'127.0.0.1','port':9}],
        'proxy-groups':[{'name':'existing','type':'select','proxies':['fake-one','fake-two']}],
        'rules':['DOMAIN,base.example,DIRECT','MATCH,existing'],
        'profile':{'store-selected':False,'store-fake-ip':False}}
config = apply(raw['clash'], copy.deepcopy(base))
assert config['rules'][-2:] == base['rules']
assert config['dns'] == base['dns'] and config['proxies'] == base['proxies']
assert len(config['rule-providers']) == 3
# In-memory dummy provider data tests the actual grammar without downloading the
# user's lists or making proxy connections in this temporary core instance.
for provider in config['rule-providers'].values():
    kind = provider['behavior']
    provider.clear()
    provider.update({'type':'inline','behavior':kind,
                     'payload':['192.0.2.0/24'] if kind == 'ipcidr' else ['+.example.test']})

def exact(conn, amount):
    out = b''
    while len(out) < amount:
        value = conn.recv(amount - len(out))
        if not value:
            raise RuntimeError('IPC closed unexpectedly')
        out += value
    return out

with tempfile.TemporaryDirectory(prefix='flclash-rules-') as folder:
    home = Path(folder)
    (home/'config.yaml').write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False))
    server = socket.socket(socket.AF_UNIX)
    ipc = str(home/'ipc.sock')
    server.bind(ipc);server.listen(1);server.settimeout(12)
    process = None;conn = None
    try:
        with (home/'parser.log').open('w') as log:
            process=subprocess.Popen(['/Applications/FlClash.app/Contents/MacOS/FlClashCore',ipc],stdout=log,stderr=log)
            conn,_=server.accept();conn.settimeout(25)
            def call(method, args):
                ident=secrets.token_hex(6)
                data=json.dumps({'id':ident,'method':method,'arguments':args}).encode()
                conn.sendall(struct.pack('<I',len(data))+data)
                while True:
                    length=struct.unpack('<I',exact(conn,4))[0]
                    assert length < 64*1024*1024
                    reply=json.loads(exact(conn,length))
                    if reply.get('id') == ident:
                        if reply.get('error'): raise RuntimeError(str(reply['error']))
                        return reply.get('result')
            assert call('initClash',{'home-dir':folder,'version':0}) is True
            result=call('setupConfig',{'selected-map':{}})
            if result: raise RuntimeError('FlClash parser rejected config: '+str(result))
    finally:
        if conn: conn.close()
        server.close()
        if process:
            try: process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired: process.kill();process.wait(timeout=3)
    assert process.poll() is not None
print(json.dumps({'stash_rules':len(stash['rules']), 'clash_rules':len(config['rules'])-2,
                  'rule_providers':3, 'flclash_core':'passed', 'tun':False, 'ports':False,
                  'temporary_core_stopped':True},ensure_ascii=False))
