"""CI-only blank-host/systemd + six protocol end-to-end acceptance; no production credentials."""
import copy,json,os,sys,subprocess,tempfile,threading,time,ssl,http.server,hashlib
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import bootstrap,agent
from onboard import defaults
from storage import save

server=defaults('ci','JP','日本','127.0.0.1',None,'example.com','/fixture','/fixture')
server['protocols']['reality'].update(cover_host='cover.example.com',cover_port=25888,sni='ci.example.com')
server['protocols']['shadowtls'].update(cover_host='cover.example.com',cover_port=25888)
with open('/etc/hosts','a') as f:f.write('\n127.0.0.1 cover.example.com\n')
# CI tunnel process has no production account; real CF API/connector is independently verified.
original_unit=bootstrap.unit
def unit(name,command,*args):return original_unit(name,'/usr/bin/sleep infinity' if name=='argo' else command,*args)
try:
 with patch.object(bootstrap,'unit',unit):result=bootstrap.install(server,'ci-fixture-only',test_certificate=True)
except Exception:
 print(subprocess.getoutput('journalctl -u xr -u sb -u argo -u caddy-sub --no-pager -n 60'));raise
assert result['installed']
state=agent.load();before={p:Path(p).read_bytes() for p in state['native_sha256']}
with patch.object(bootstrap,'unit',unit):bootstrap.install(server,'ci-fixture-only',test_certificate=True)
assert before=={p:Path(p).read_bytes() for p in before}
# TLS 1.3 cover server for REALITY and ShadowTLS; never relies on an external website.
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b'fleet-native-ok')
 def log_message(self,*args):pass
plain=http.server.ThreadingHTTPServer(('127.0.0.1',25889),Handler)
cover=http.server.ThreadingHTTPServer(('127.0.0.1',25888),Handler)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.set_alpn_protocols(['h2','http/1.1']);ctx.load_cert_chain(server['certificates']['domain']['certificate_file'],server['certificates']['domain']['key_file']);cover.socket=ctx.wrap_socket(cover.socket,server_side=True)
for service in (plain,cover):threading.Thread(target=service.serve_forever,daemon=True).start()
# Build clients from actual exported credentials.
from protocols import export
nodes=export(agent.configs(state),state)['proxies']
for node in nodes:
 ident=node['name'][6:];p=server['protocols'][ident]
 out={'type':node['type'],'tag':'proxy','server':'127.0.0.1','server_port':p['port']};extras=[]
 tls={'enabled':True,'server_name':p.get('sni','ci.example.com'),'certificate_path':server['certificates']['domain']['certificate_file']}
 if ident=='reality':out.update(uuid=node['uuid'],flow=node['flow'],tls={'enabled':True,'server_name':p['sni'],'utls':{'enabled':True,'fingerprint':'chrome'},'reality':{'enabled':True,'public_key':node['reality-opts']['public-key'],'short_id':node['reality-opts']['short-id']}})
 elif ident=='cf':out.update(uuid=node['uuid'],security='auto',transport={'type':'ws','path':p['ws_path']})
 elif ident in ('hy2','salamander'):out.update(type='hysteria2',password=node['password'],tls=tls)
 elif ident=='anytls':out.update(password=node['password'],tls=tls)
 else:
  out={'type':'shadowsocks','tag':'proxy','server':'127.0.0.1','server_port':p['port'],'method':node['cipher'],'password':node['password'],'detour':'shadow','udp_over_tcp':{'enabled':True,'version':2}}
  extras=[{'type':'shadowtls','tag':'shadow','server':'127.0.0.1','server_port':p['port'],'version':3,'password':node['plugin-opts']['password'],'tls':{'enabled':True,'server_name':'ci.example.com','insecure':True,'utls':{'enabled':True,'fingerprint':'chrome'}}}]
 if ident=='salamander':out['obfs']={'type':'salamander','password':node['obfs-password']}
 cfg={'log':{'level':'warn'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':25890}],'outbounds':[out]+extras}
 save('/tmp/fleet-ci-client.json',cfg)
 with open('/tmp/fleet-ci-client.log','w') as log:
  proc=subprocess.Popen(['/root/agsbx/sing-box','run','-c','/tmp/fleet-ci-client.json'],stdout=log,stderr=log)
  try:
   time.sleep(1)
   response=subprocess.run(['curl','--noproxy','','--socks5-hostname','127.0.0.1:25890','--max-time','15','-fsS','http://127.0.0.1:25889'],capture_output=True,text=True)
   if response.returncode or response.stdout!='fleet-native-ok':
    print(Path('/tmp/fleet-ci-client.log').read_text());print(subprocess.getoutput('journalctl -u xr -u sb --no-pager -n 25'));raise AssertionError(ident+' client failed: '+response.stderr)
   print('PASS actual client',ident,flush=True)
  finally:proc.terminate();proc.wait(timeout=10)
# Exercise the exact onboarding probe using a private HTTPS + UDP echo fixture.
import probe,socket,struct
echo=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);echo.bind(('127.0.0.1',25891))
def echo_loop():
 while True:
  try:
   data,addr=echo.recvfrom(4096);echo.sendto(data,addr)
  except OSError:return
threading.Thread(target=echo_loop,daemon=True).start()
def probe_https(port):
 raw,_=probe.socks(port,'127.0.0.1',25888)
 context=ssl.create_default_context(cafile=server['certificates']['domain']['certificate_file'])
 with raw,context.wrap_socket(raw,server_hostname='ci.example.com') as stream:
  stream.sendall(b'GET / HTTP/1.1\r\nHost: ci.example.com\r\nConnection: close\r\n\r\n')
  response=probe.http.client.HTTPResponse(stream);response.begin();assert response.read()==b'fleet-native-ok'
 return '127.0.0.1'
def probe_udp(port):
 stream,relay=probe.socks(port,'0.0.0.0',0,True)
 with stream,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
  sock.settimeout(10);data=b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',25891)+b'fleet-udp'
  sock.sendto(data,relay);got,_=sock.recvfrom(4096);return got.endswith(b'fleet-udp')
def checked(fn):
 def run(port):
  try:return fn(port)
  except Exception:
   import traceback
   traceback.print_exc();raise
 return run
for n in nodes:
 n=copy.deepcopy(n);ident=n['name'][6:];n['server']='127.0.0.1';n['_certificate_path']=server['certificates']['domain']['certificate_file']
 if ident=='cf':n['tls']=False;n['port']=server['protocols']['cf']['port']
 if ident=='shadowtls':n['plugin-opts']['host']='ci.example.com'
 result=probe.check_case({'name':ident,'node':n,'expected_ips':['127.0.0.1']},https_check=checked(probe_https),udp_check=checked(probe_udp))
 assert all(result[k] for k in ('https_ok','exit_ok','udp_ok')),result
 print('PASS onboarding HTTPS/UDP probe',ident,flush=True)
echo.close()
# Create/edit/delete a second same-type listener through installed agent interfaces.
desired=copy.deepcopy(server['protocols']);desired['anytls_second']={**desired['anytls'],'type':'anytls','port':25447}
assert agent.plan({'protocols':desired})['added']==['anytls_second']
agent.apply(True);assert len(agent.load()['protocols'])==7
assert any(p['port']==25447 for p in export(agent.configs(agent.load()),agent.load())['proxies'])
agent.plan({'protocols':server['protocols']});agent.apply(True)
assert before=={p:Path(p).read_bytes() for p in before}
print('PASS blank install, resume, native clients, second inbound add/remove, original credentials/config restored',flush=True)
