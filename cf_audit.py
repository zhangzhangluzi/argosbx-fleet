"""Audit scoped Cloudflare access using GET only; never test writes on real DNS."""
import re
from urllib.parse import urlencode

from protocols import protocol_type

PERMISSIONS={
    'dns_edit':({'4755a26eedb94da69e1066d98aa820be'},{'DNS Write','DNS Edit'}),
    'tunnel_edit':({'c07321b023e944ff818fec44d8203567'},{'Cloudflare Tunnel Write','Cloudflare Tunnel Edit'}),
}


def failure(error):
    status=getattr(error,'status',None)
    return {'status':'denied' if status in (401,403) else 'unavailable',
            'http_status':status,'api_codes':list(getattr(error,'codes',()))}


def scope_matches(resources,account,zone=None):
    if not isinstance(resources,dict):return False
    accepted={'*','com.cloudflare.api.account.*','com.cloudflare.api.account.'+account}
    if zone:accepted|={'com.cloudflare.api.account.zone.*','com.cloudflare.api.account.zone.'+zone}
    for key,value in resources.items():
        if key in accepted and value=='*':return True
        if key in accepted and isinstance(value,dict) and scope_matches(value,account,zone):return True
    return False


def declared_permission(metadata,permission,account,zone=None):
    if metadata is None:return 'not_verified'
    ids,names=PERMISSIONS[permission];allowed=False
    for policy in metadata.get('policies',[]):
        if not scope_matches(policy.get('resources',{}),account,zone):continue
        if not any(p.get('id') in ids or p.get('name') in names for p in policy.get('permission_groups',[])):continue
        if policy.get('effect')=='deny':return 'not_granted'
        if policy.get('effect')=='allow':allowed=True
    return 'declared_granted' if allowed else 'not_granted'


def audit(cf,server):
    result={'server':server['id'],'read_only':True,'writes_tested':False,
            'token':{'status':'not_verified'},'zones':[],'metadata_read':False,
            'requirements':{'certificate_dns01':['Zone DNS Edit for selected zone + explicit Zone ID'],
                            'fleet':['Zone Read','DNS Edit','Account Cloudflare Tunnel Edit']}}
    hosts={h for h in server.get('domains',{}).values() if h}
    hosts|={p['sni'] for p in server['protocols'].values() if p['enabled'] and p.get('certificate')}
    cf_hosts={p['sni'] for ident,p in server['protocols'].items() if p['enabled'] and protocol_type(ident,p) in ('cf','xhttp')}
    hosts|=cf_hosts
    try:zones=cf.zones()
    except RuntimeError as error:
        result['zone_access']=failure(error);result['status']='needs_attention'
        return result
    matched={}
    for host in sorted(hosts):
        found=sorted((z for z in zones if host==z['name'] or host.endswith('.'+z['name'])),key=lambda z:len(z['name']),reverse=True)
        if not found:
            result.setdefault('unavailable_hosts',[]).append(host)
        else:matched.setdefault(found[0]['id'],(found[0],[]))[1].append(host)
    token=None;owner=None
    for base in ['/user/tokens']+['/accounts/'+a+'/tokens' for a in sorted({z['account']['id'] for z,_ in matched.values()})]:
        try:
            value=cf.call(base+'/verify')['result']
            if value.get('status')!='active':
                result['token']={'status':value.get('status','not_verified')};continue
            token=value;owner=base;result['token']={k:value[k] for k in ('status','expires_on','not_before') if k in value};break
        except RuntimeError as error:result['token']['verify_error']=failure(error)
    metadata=None
    if token and re.fullmatch(r'[a-fA-F0-9]{32}',str(token.get('id',''))):
        try:
            metadata=cf.call(owner+'/'+token['id'])['result'];result['metadata_read']=True
            condition=metadata.get('condition',{}).get('request.ip',{})
            result['source_ip_filter']={'configured':bool(condition),'allowed_ranges':condition.get('in',[]),'excluded_ranges':condition.get('not_in',[]),
                                        'actual_api_source_ip':'not_observed','compromised_allowed_host_still_risky':True}
        except RuntimeError as error:result['metadata_error']=failure(error)
    if metadata is None:result['source_ip_filter']={'configured':None,'status':'not_verified'}
    tunnels={}
    for zone,zone_hosts in matched.values():
        account=zone['account']['id'];row={'name':zone['name'],'active':zone.get('status')=='active','dns':[],
                                         'dns_edit':declared_permission(metadata,'dns_edit',account,zone['id'])}
        for host in zone_hosts:
            try:
                records=cf.call('/zones/'+zone['id']+'/dns_records?'+urlencode({'name':host,'per_page':100}))['result']
                row['dns'].append({'host':host,'read':'passed','records':len(records)})
                for record in records:
                    content=record.get('content','')
                    if host in cf_hosts and record.get('type')=='CNAME' and content.endswith('.cfargotunnel.com'):
                        tid=content[:-len('.cfargotunnel.com')]
                        if re.fullmatch(r'[a-fA-F0-9-]{36}',tid):tunnels.setdefault((account,tid),set()).add(host)
            except RuntimeError as error:row['dns'].append({'host':host,'read':failure(error)})
        result['zones'].append(row)
    result['tunnels']=[]
    for (account,ident),tunnel_hosts in tunnels.items():
        row={'hosts':sorted(tunnel_hosts),'tunnel_edit':declared_permission(metadata,'tunnel_edit',account)}
        try:
            value=cf.call('/accounts/'+account+'/cfd_tunnel/'+ident+'/configurations')['result']
            row['config_read']='passed' if isinstance(value.get('config'),dict) else 'invalid_response'
        except RuntimeError as error:row['config_read']=failure(error)
        result['tunnels'].append(row)
    result['unresolved_cf_hosts']=sorted(cf_hosts-{h for hosts in tunnels.values() for h in hosts})
    reads=bool(matched) and all(z['active'] and all(d['read']=='passed' for d in z['dns']) for z in result['zones'])
    reads=reads and not result.get('unavailable_hosts') and not result['unresolved_cf_hosts'] and all(t['config_read']=='passed' for t in result['tunnels'])
    declarations=[z['dns_edit'] for z in result['zones']]+[t['tunnel_edit'] for t in result['tunnels']]
    result['read_access_passed']=bool(reads)
    result['write_policy_status']='not_granted' if 'not_granted' in declarations else 'not_verified' if not declarations or 'not_verified' in declarations else 'declared_granted'
    result['status']='needs_attention' if not reads or result['write_policy_status']=='not_granted' or result['token']['status'] not in ('active','not_verified') else 'passed' if result['write_policy_status']=='declared_granted' and result['token']['status']=='active' else 'partial'
    return result
