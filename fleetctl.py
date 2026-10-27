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
    p=argparse.ArgumentParser();p.add_argument('command',choices=['inspect','protocol-plan','protocol-apply','protocol-recover','domain-plan','domain-stage','domain-commit','domain-recover','xhttp-stage','xhttp-commit','xhttp-recover','diagnose','certificate-audit','cf-audit']);p.add_argument('--config');p.add_argument('--server',required=True);p.add_argument('--allow-restart',action='store_true');p.add_argument('--observer');checks=p.add_mutually_exclusive_group();checks.add_argument('--verify-writes',action='store_true');checks.add_argument('--recover-writes',action='store_true');a=p.parse_args()
    config=read(a.config);server=servers(config)[a.server]
    if a.observer and a.command not in ('diagnose','certificate-audit'):raise ValueError('--observer 只用于独立诊断或证书验收')
    if (a.verify_writes or a.recover_writes) and a.command!='cf-audit':raise ValueError('写权限验证只适用于 cf-audit')
    if a.command in ('diagnose','certificate-audit','cf-audit'):
        if a.allow_restart:raise ValueError('维护验收不接受 --allow-restart')
        if a.command=='diagnose':
            import diagnostics
            result=diagnostics.run(config,server,remote,a.observer)
        elif a.command=='certificate-audit':
            import certificates
            result=certificates.run(config,server,remote,a.observer)
        else:
            import cf_audit,cf_probe
            from fleet import resolve_path
            cf=Cloudflare.from_config(config)
            journal=STATE/(a.server+'-cf-permission-check.json')
            if a.recover_writes:result={**cf_probe.recover(cf,journal),'read_only':False}
            else:
                policy=config['cloudflare'].get('policy_snapshot')
                result=cf_audit.audit(cf,server,resolve_path(policy) if policy else None)
                if a.verify_writes:
                    result['write_verification']=cf_probe.verify(cf,server,journal)
                    result['writes_tested']=True;result['read_only']=False
    elif a.command.startswith('xhttp-'):
        import tunnels
        cf=Cloudflare.from_config(config);journal=STATE/(a.server+'-xhttp-cf-journal.json')
        if a.command=='xhttp-stage':
            previous=remote(config,a.server,'inspect')['protocols']
            result=remote(config,a.server,'xhttp-stage',server['protocols']['xhttp'])
            if not journal.exists():
                scoped=copy.deepcopy(server);scoped['protocols']={**previous,'xhttp':server['protocols']['xhttp']}
                plan=tunnels.change_plan(cf,scoped,previous)
                if plan:stage(cf,plan,journal)
            result['verification_pending']=True
        elif a.command=='xhttp-commit':
            if not journal.exists():raise ValueError('CF 路由验收日志缺失')
            j=json.loads(journal.read_text());plan=j['plan']
            if not j['ready'] or cf.call(plan['tunnel_path'])['result']['config']!=plan['after']:raise ValueError('CF 路由尚未就绪或已变化')
            live=remote(config,a.server,'inspect')
            if 'xhttp-journal.json' not in live['unfinished_transactions']:
                if live['protocols'].get('xhttp')!=server['protocols']['xhttp'] or not all(live.get(k) for k in ('native_configuration_matches','services_active','source_matches')):
                    raise ValueError('XHTTP 提交状态不匹配，保留 CF 日志')
                result={'committed':True,'existing_services_restarted':False}
            else:result=remote(config,a.server,'xhttp-commit')
            journal.unlink()
        else:
            # Restore only owned CF changes, then remove only the staged service.
            if journal.exists():recover(cf,journal)
            result=remote(config,a.server,'xhttp-recover')
    elif a.command=='inspect':result=remote(config,a.server,'inspect')
    elif a.command=='protocol-plan':result=remote(config,a.server,'plan',{'protocols':server['protocols'],'certificates':server['certificates']})
    elif a.command=='protocol-apply':
        import tunnels
        checked=remote(config,a.server,'planned')
        if checked['protocols']!=server['protocols'] or checked['certificates']!=server['certificates']:raise ValueError('资料在计划后变化，请重新 protocol-plan')
        previous=checked['previous_protocols']
        if checked['restart_required'] and not a.allow_restart:raise ValueError('新入站需要原生服务重启；未修改服务或 Cloudflare，请在维护窗口使用 --allow-restart')
        cf_changed=tunnels.routes({'protocols':previous})!=tunnels.routes(server)
        cf=None;cf_journal=STATE/(a.server+'-protocol-cf.json')
        if cf_changed:
            cf=Cloudflare.from_config(config)
            if cf_journal.exists():raise ValueError('CF 入站有未完成事务，先执行 protocol-recover')
            cf_plan=tunnels.change_plan(cf,server,previous)
            if cf_plan:
                cf_plan.update(protocols_before=previous,protocols_after=server['protocols'])
                stage(cf,cf_plan,cf_journal)
        try:result=remote(config,a.server,'apply',allow_restart=a.allow_restart)
        except Exception:
            # Unknown SSH result: retain CF changes until native state is recovered.
            raise RuntimeError('应用结果未确认；保留 CF/原生恢复日志，请执行 protocol-recover') from None
        cf_journal.unlink(missing_ok=True)
        result['cf_synchronized']=cf_changed
    elif a.command=='protocol-recover':
        cf_journal=STATE/(a.server+'-protocol-cf.json')
        result=remote(config,a.server,'recover',allow_restart=a.allow_restart)
        if cf_journal.exists():
            cf=Cloudflare.from_config(config)
            # If the native apply committed but its SSH reply was lost, keep the matching routes.
            current=remote(config,a.server,'inspect')['protocols']
            saved=json.loads(cf_journal.read_text())['plan']
            if current==saved['protocols_after']:cf_journal.unlink()
            elif current==saved['protocols_before']:recover(cf,cf_journal)
            else:raise ValueError('原生入站被其他操作修改，保留 CF 恢复日志')
    else:
        domain_plan=STATE/(a.server+'-domain-plan.json');journal=STATE/(a.server+'-domain-journal.json')
        cf=Cloudflare.from_config(config)
        if a.command=='domain-plan':
            if journal.exists():raise ValueError('域名迁移未完成，请先恢复；未覆盖原计划')
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
            if plan['names'].get('certificate') and not (j.get('certificate') or {}).get('ready'):
                raise ValueError('证书阶段未完成，请先 domain-recover；未修改协议或订阅')
            updated=copy.deepcopy(config)
            from protocols import migrate_references
            target=migrate_references(server,plan['names'],j['certificate']['certificate'] if j.get('certificate') else None)
            updated['servers']=[target if s['id']==a.server else s for s in updated['servers']]
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
                    remote(old,a.server,'recover',allow_restart=a.allow_restart)
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
