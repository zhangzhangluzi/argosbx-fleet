"""Parse every generated classical part in an isolated installed FlClash core."""
import json,secrets,socket,struct,subprocess,sys,tempfile,time
from pathlib import Path
import yaml

input_path=Path(sys.argv[1]);parts=json.loads(input_path.read_text())
order=[('magic-dns','DIRECT'),('dns-block','REJECT'),('process','DIRECT'),('dns-dot','日常线路'),
       ('priority-direct','DIRECT'),('priority-proxy','日常线路'),('china-console','DIRECT'),
       ('foreign-console','日常线路'),('dns-direct','DIRECT'),('dns-proxy-1','日常线路'),
       ('google-dns','日常线路'),('dns-proxy-2','日常线路'),('telegram','Telegram'),
       ('ads','去广告'),('lan','DIRECT'),('ai','AI线路'),('china-sites','DIRECT'),
       ('overseas','日常线路'),('china-domains','DIRECT'),('china-ip','DIRECT'),('udp','日常线路')]

def exact(conn,n):
    out=b''
    while len(out)<n:
        value=conn.recv(n-len(out))
        if not value:raise RuntimeError('IPC closed')
        out+=value
    return out

with tempfile.TemporaryDirectory(prefix='flclash-rule-provider-') as folder:
    home=Path(folder);(home/'rules').mkdir();providers={};counts={}
    for name,_ in order:
        if name in ('ads','china-domains','china-ip'):
            behavior='ipcidr' if name=='china-ip' else 'domain'
            mrs=input_path.parent/(name+'.mrs')
            if mrs.exists():
                (home/'rules'/f'{name}.mrs').write_bytes(mrs.read_bytes())
                providers[name]={'type':'file','behavior':behavior,'format':'mrs','path':f'./rules/{name}.mrs'}
                counts[name]=None
            else:
                providers[name]={'type':'inline','behavior':behavior,
                                 'payload':['192.0.2.0/24'] if behavior=='ipcidr' else ['+.example.test']}
            continue
        text=parts[name]['body'];lines=[line for line in text.splitlines() if line]
        assert lines and not any('日常线路' in x or 'AI线路' in x or 'Telegram' in x for x in lines)
        (home/'rules'/f'{name}.txt').write_text(text)
        providers[name]={'type':'file','behavior':'classical','format':'text','path':f'./rules/{name}.txt'}
        counts[name]=len(lines)
    groups=[{'name':name,'type':'select','proxies':['fake']} for name in ('日常线路','AI线路','Telegram')]
    groups.append({'name':'去广告','type':'select','proxies':['REJECT','日常线路']})
    config={'mixed-port':0,'port':0,'socks-port':0,'allow-lan':False,'bind-address':'127.0.0.1',
            'tun':{'enable':False},'dns':{'enable':False},'geo-auto-update':False,'log-level':'warning',
            'find-process-mode':'off','proxies':[{'name':'fake','type':'socks5','server':'127.0.0.1','port':9}],
            'proxy-groups':groups,'rule-providers':providers,
            'rules':[f'RULE-SET,{name},{target}' for name,target in order]+['MATCH,日常线路'],
            'profile':{'store-selected':False,'store-fake-ip':False}}
    (home/'config.yaml').write_text(yaml.safe_dump(config,allow_unicode=True,sort_keys=False))
    server=socket.socket(socket.AF_UNIX);ipc=str(home/'ipc.sock');server.bind(ipc);server.listen(1);server.settimeout(12)
    process=None;conn=None
    try:
        with (home/'parser.log').open('w') as log:
            process=subprocess.Popen(['/Applications/FlClash.app/Contents/MacOS/FlClashCore',ipc],stdout=log,stderr=log)
            conn,_=server.accept();conn.settimeout(25)
            def call(method,args=None):
                ident=secrets.token_hex(6);data=json.dumps({'id':ident,'method':method,'arguments':args}).encode()
                conn.sendall(struct.pack('<I',len(data))+data)
                while True:
                    length=struct.unpack('<I',exact(conn,4))[0];assert length<64*1024*1024
                    value=json.loads(exact(conn,length))
                    if value.get('id')==ident:
                        if value.get('error'):raise RuntimeError(str(value['error']))
                        return value.get('result')
            assert call('initClash',{'home-dir':folder,'version':0}) is True
            result=call('setupConfig',{'selected-map':{}})
            if result:raise RuntimeError('core rejected config: '+str(result))
            until=time.monotonic()+10
            while True:
                external=call('getExternalProviders')
                actual={x['name']:x['count'] for x in external}
                matches=(set(actual)==set(counts) and all(actual[name]>0 if count is None else actual[name]==count
                                                         for name,count in counts.items()))
                if matches or time.monotonic()>=until:break
                time.sleep(0.1)
            if not matches:
                log.flush()
                details=(home/'parser.log').read_text()[-1800:]
                raise RuntimeError('rule-provider entry counts differ: '+str({'expected':counts,'actual':actual,'log':details}))
    finally:
        if conn:conn.close()
        server.close()
        if process:
            try:process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
    assert process.poll() is not None
print(json.dumps({'classical_providers':sum(v is not None for v in counts.values()),
                  'mrs_providers':sum(v is None for v in counts.values()),
                  'all_entries_parsed':sum(actual.values()),
                  'isolated_core_stopped':True,'tun':False,'ports':False}))
