"""Exercise live standard-provider URLs in an isolated FlClash core."""
import json,secrets,socket,struct,subprocess,sys,tempfile,time,urllib.parse
from pathlib import Path
import yaml

state=json.loads(Path(sys.argv[1]).read_text());token=state['tokens']['stash']
root=state['provider_origin'].rstrip('/')+'/rules/providers/'
spec=[('ai','classical','text'),('telegram','classical','text'),('ads','domain','mrs'),
      ('china-domains','domain','mrs'),('china-ip','ipcidr','mrs')]
def exact(conn,n):
    out=b''
    while len(out)<n:
        b=conn.recv(n-len(out))
        if not b:raise RuntimeError('IPC closed')
        out+=b
    return out

with tempfile.TemporaryDirectory(prefix='flclash-remote-providers-') as folder:
    home=Path(folder);providers={}
    for name,behavior,fmt in spec:
        providers[name]={'type':'http','behavior':behavior,'format':fmt,
            'url':root+'standard.'+('mrs' if fmt=='mrs' else 'txt')+'?'+urllib.parse.urlencode({'token':token,'part':name}),
            'path':'./rules/'+name+'.'+fmt,'interval':86400}
    config={'mixed-port':0,'port':0,'socks-port':0,'allow-lan':False,'bind-address':'127.0.0.1',
       'tun':{'enable':False},'dns':{'enable':False},'geo-auto-update':False,'log-level':'error',
       'rule-providers':providers,'rules':['RULE-SET,'+name+',DIRECT' for name,_,_ in spec]+['MATCH,DIRECT'],
       'profile':{'store-selected':False,'store-fake-ip':False}}
    (home/'config.yaml').write_text(yaml.safe_dump(config,allow_unicode=True,sort_keys=False))
    server=socket.socket(socket.AF_UNIX);ipc=str(home/'ipc.sock');server.bind(ipc);server.listen(1);server.settimeout(12)
    process=None;conn=None
    try:
        with (home/'core.log').open('w') as log:
            process=subprocess.Popen(['/Applications/FlClash.app/Contents/MacOS/FlClashCore',ipc],stdout=log,stderr=log)
            conn,_=server.accept();conn.settimeout(15)
            def call(method,args=None):
                ident=secrets.token_hex(6);b=json.dumps({'id':ident,'method':method,'arguments':args}).encode()
                conn.sendall(struct.pack('<I',len(b))+b)
                while True:
                    size=struct.unpack('<I',exact(conn,4))[0];v=json.loads(exact(conn,size))
                    if v.get('id')==ident:
                        if v.get('error'):raise RuntimeError('core IPC error')
                        return v.get('result')
            assert call('initClash',{'home-dir':folder,'version':0}) is True
            assert not call('setupConfig',{'selected-map':{}})
            end=time.monotonic()+48
            while True:
                found={x['name']:x['count'] for x in call('getExternalProviders')}
                if len(found)==len(spec) and all(found.get(name,0)>0 for name,_,_ in spec):break
                if time.monotonic()>=end:raise RuntimeError('remote providers did not all load; counts='+str(found))
                time.sleep(0.25)
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
print(json.dumps({'actual_http_providers_loaded':len(found),'counts':found,'tun':False,'ports':False,'temporary_core_stopped':True}))
