"""Disposable native Caddy gzip/auth/scope acceptance; never restarts a service."""
import gzip,http.client,http.server,json,os,subprocess,sys,tempfile,threading,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from country_routes import compression_render

BODY=b'fleet-native-compression\n'*512
class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        valid=self.path.endswith('?token=fixture-only')
        self.send_response(200 if valid else 401)
        self.send_header('Content-Type','text/plain; charset=utf-8');self.end_headers()
        self.wfile.write(BODY if valid else b'Unauthorized')
    def log_message(self,*args):pass

backend=http.server.ThreadingHTTPServer(('127.0.0.1',3001),Backend)
thread=threading.Thread(target=backend.serve_forever,daemon=True);thread.start()
shares='''# BEGIN EXTERNAL SEVEN SHARES
@external_seven_share path /share/col/external-seven /share/file/external-seven-shadowrocket-config /share/file/external-seven-shadowrocket-ads /share/file/external-seven-de-mia-ingress
handle @external_seven_share {
 header Cache-Control "private, no-store"
 header Vary "User-Agent"
 reverse_proxy 127.0.0.1:3001
}
# END EXTERNAL SEVEN SHARES
'''
def request(path,encoding):
    connection=http.client.HTTPConnection('127.0.0.1',25894,timeout=5)
    try:
        connection.request('GET',path,headers={'Accept-Encoding':encoding,'User-Agent':'Stash/3.6.2'})
        response=connection.getresponse();return response.status,{k:response.getheader(k) for k in response.headers},response.read()
    finally:connection.close()
try:
    with tempfile.TemporaryDirectory(prefix='fleet-ci-compression-') as directory:
        root=Path(directory);config=root/'Caddyfile'
        config.write_text('{\n admin off\n}\nhttp://127.0.0.1:25894 {\n'+compression_render(shares)+'\n respond "outside" 404\n}\n')
        subprocess.run(['/usr/local/bin/caddy','validate','--config',str(config),'--adapter','caddyfile'],capture_output=True,check=True)
        with (root/'caddy.log').open('w') as log:
            process=subprocess.Popen(['/usr/local/bin/caddy','run','--config',str(config),'--adapter','caddyfile'],stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if process.poll() is not None:raise RuntimeError('Caddy fixture exited')
                    try:
                        if request('/outside','identity')[0]==404:break
                    except OSError:pass
                    time.sleep(.05)
                else:raise RuntimeError('Caddy fixture unavailable')
                for path in ['/share/col/external-seven','/share/file/external-seven-shadowrocket-config','/share/file/external-seven-shadowrocket-ads','/share/file/external-seven-de-mia-ingress']:
                    status,headers,plain=request(path+'?token=fixture-only','identity')
                    assert status==200 and plain==BODY and 'Content-Encoding' not in headers
                    status,headers,compressed=request(path+'?token=fixture-only','gzip')
                    assert status==200 and headers.get('Content-Encoding')=='gzip'
                    assert gzip.decompress(compressed)==plain and len(compressed)<len(plain)//4
                    assert headers.get('Cache-Control')=='private, no-store'
                    vary={v.strip().lower() for v in headers.get('Vary','').split(',')}
                    assert {'accept-encoding','user-agent'}<=vary,headers
                    assert request(path,'gzip')[0]==401
                assert request('/api/private?token=fixture-only','gzip')[0]==404
                print('PASS native share gzip bytes, private/Vary headers, unchanged auth and exact path scope',flush=True)
            finally:
                process.terminate();process.wait(timeout=10)
finally:backend.shutdown();backend.server_close();thread.join(5)
