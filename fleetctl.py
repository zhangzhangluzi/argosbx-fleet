#!/usr/bin/env python3
"""Single inventory to native agents and the unchanged Sub-Store publication."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
from fleet import read,servers,ssh_args,STATE,DEFAULT
from storage import save,lock
from domains import Cloudflare,build,stage,recover

def remote(config,server,command,payload=None,allow_restart=False):
    args=ssh_args(server,config)+['python3 -B /opt/argosbx-fleet/current/agent.py '+command+(' --allow-restart' if allow_restart else '')]
    p=subprocess.run(args,input=json.dumps(payload) if payload is not None else '',text=True,capture_output=True,timeout=180)
    if p.returncode:raise RuntimeError(server+': '+p.stderr.strip()[:400])
    return json.loads(p.stdout)

def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['inspect','protocol-plan','protocol-apply','protocol-recover','domain-plan','domain-stage','domain-commit','domain-recover']);p.add_argument('--config');p.add_argument('--server',required=True);p.add_argument('--allow-restart',action='store_true');a=p.parse_args()
    config=read(a.config);server=servers(config)[a.server]
    if a.command=='inspect':result=remote(config,a.server,'inspect')
    elif a.command=='protocol-plan':result=remote(config,a.server,'plan',{'protocols':server['protocols'],'certificates':server['certificates']})
    elif a.command=='protocol-apply':result=remote(config,a.server,'apply',allow_restart=a.allow_restart)
    elif a.command=='protocol-recover':result=remote(config,a.server,'recover')
    else:
        domain_plan=STATE/(a.server+'-domain-plan.json');journal=STATE/(a.server+'-domain-journal.json')
        cf=Cloudflare(config['cloudflare']['token_file'])
        if a.command=='domain-plan':
            desired=server['domain_migration'];plan=build(cf,desired['zone'],server,desired['names'],desired['tunnel_id'])
            plan['inventory']=copy.deepcopy(config);save(domain_plan,plan)
            result={'dns_changes':len(plan['records']),'tunnel_changes':plan['before']!=plan['after'],'original_subscription_preserved':True}
        elif a.command=='domain-stage':
            plan=json.loads(domain_plan.read_text())
            if plan['inventory']!=config:raise ValueError('资料已变化，重新 domain-plan')
            result=stage(cf,plan,journal)
            if plan['names'].get('certificate'):
                try:result['certificate']=remote(config,a.server,'certificate',{'hostname':plan['names']['certificate']})
                except Exception:recover(cf,journal);raise
            saved=json.loads(journal.read_text());saved['certificate']=result.get('certificate');save(journal,saved)
        elif a.command=='domain-commit':
            j=json.loads(journal.read_text());plan=j['plan']
            if not j['ready'] or config!=plan['inventory']:raise ValueError('迁移计划未就绪或已过期')
            updated=copy.deepcopy(config);target=servers(updated)[a.server]
            for role,name in plan['names'].items():
                if role!='certificate':target['domains'][role]=name
            if target['domains']['cf']:target['protocols']['cf']['sni']=target['domains']['cf']
            # Certificate switches use one explicit reference across TLS protocols.
            if j.get('certificate'):
                target['certificates']['domain']=j['certificate']['certificate']
                for ident in ('hy2','anytls','salamander'):
                    target['protocols'][ident].update(certificate='domain',sni=plan['names']['certificate'])
            import socket,ipaddress
            # Confirm DNS before touching protocol identities or subscription objects.
            for role in ('ipv4','ipv6'):
                host=target['domains'][role]
                if not host:continue
                family=socket.AF_INET if role=='ipv4' else socket.AF_INET6
                addresses=socket.getaddrinfo(host,None,family)
                if not any(ipaddress.ip_address(x[4][0])==ipaddress.ip_address(target[role]) for x in addresses):raise ValueError('DNS 尚未指向目标服务器')
            planned=remote(config,a.server,'plan',{'protocols':target['protocols'],'certificates':target['certificates']})
            if planned['restart_required'] and not a.allow_restart:raise ValueError('新证书需重载协议进程；已保留旧入口，待维护窗口加 --allow-restart 后提交')
            j['protocol_commit_attempted']=True;j['target_inventory']=updated;save(journal,j)
            original_path=Path(a.config or os.environ.get('ARGOSBX_SERVERS_FILE',DEFAULT))
            candidate=STATE/(a.server+'-domain-candidate.json');save(candidate,updated)
            os.environ['ARGOSBX_SERVERS_FILE']=str(candidate)
            import servers as publisher
            from lease import coordinator
            try:
                remote(config,a.server,'apply',allow_restart=a.allow_restart)
                with lock(STATE/'publisher.lock'),coordinator(config):
                    prepared=publisher.prepare(updated)
                    j['publication_plan']=prepared;save(journal,j)
                    publisher.publish(updated)
                save(original_path,updated)
            except Exception:
                # Keep the durable migration journal. Explicit recovery must first
                # restore the subscription transaction, then the native parameters.
                raise RuntimeError('提交未完成；保留域名日志，执行 domain-recover 恢复') from None
            j['committed']=True;save(journal,j)
            domain_plan.unlink(missing_ok=True);candidate.unlink(missing_ok=True);journal.unlink()
            result={'inventory_updated':True,'subscription_preserved':True,'publication_verified':True,'old_dns_retained':True}
        else:
            if journal.exists() and json.loads(journal.read_text()).get('committed'):raise ValueError('已提交域名引用，不能单独删除 DNS；先恢复配置与订阅')
            if journal.exists():
                j=json.loads(journal.read_text())
                if j.get('protocol_commit_attempted'):
                    from lease import coordinator
                    import servers as publisher,publication
                    with lock(STATE/'publisher.lock'),coordinator(config):
                        publication.recover(publisher.JOURNAL,config,publisher.get,publisher.request,publisher.digest)
                        publication.recover(publisher.STAGING,config,publisher.get,publisher.request,publisher.digest)
                        if j.get('publication_plan'):
                            recovery=STATE/(a.server+'-domain-publication-restore.json')
                            save(recovery,{'backend_sha256':publisher.digest(config['subscription']['backend_url']),'attempted':j['publication_plan']['items'],'temporary':[]})
                            publication.recover(recovery,config,publisher.get,publisher.request,publisher.digest)
                    old=j['plan']['inventory'];original=servers(old)[a.server]
                    # If the native apply was interrupted, recover its file journal first.
                    remote(old,a.server,'recover')
                    p=remote(old,a.server,'plan',{'protocols':original['protocols'],'certificates':original['certificates']})
                    if p['restart_required'] and not a.allow_restart:raise ValueError('恢复原证书需维护窗口 --allow-restart；DNS 尚未删除')
                    remote(old,a.server,'apply',allow_restart=a.allow_restart)
                    save(Path(a.config or os.environ.get('ARGOSBX_SERVERS_FILE',DEFAULT)),old)
            remote(config,a.server,'certificate-recover');recover(cf,journal);result={'restored':True}
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':
    try:
        with lock(STATE/'fleet.lock'):main()
    except Exception as e:
        print(str(e) if isinstance(e,(ValueError,RuntimeError)) else type(e).__name__,file=sys.stderr);sys.exit(1)
