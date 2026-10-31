"""Stage one additional loopback XHTTP service without touching existing listeners."""
import copy,json,yaml
from pathlib import Path
import agent
from inbounds import create,engines
from protocols import validate_settings,export
from storage import save,atomic

CONFIG=Path('/root/agsbx/xr-xhttp.json')
UNIT=Path('/etc/systemd/system/argosbx-xhttp.service')
SERVICE='argosbx-xhttp.service'

def journal():return agent.HOME/'xhttp-journal.json'

def stage(settings):
    validate_settings({'xhttp':settings},complete=True)
    if not settings['enabled']:raise ValueError('新增入口必须启用')
    if journal().exists():
        j=json.loads(journal().read_text())
        if j['settings']!=settings:raise ValueError('XHTTP 事务待恢复')
        if not j.get('ready'):raise ValueError('XHTTP 启动结果未确认，先恢复')
        agent.cmd(['systemctl','is-active','--quiet',SERVICE])
        return {'ready':True,'existing_services_restarted':False}
    if agent.JOURNAL.exists():raise ValueError('已有原生事务待恢复')
    state=agent.load();before=agent.configs(state)
    if 'xhttp' in state['protocols'] or CONFIG.exists() or UNIT.exists():raise ValueError('XHTTP 已存在，使用正常协议管理')
    if any(agent.sha(Path(p).read_text())!=h for p,h in state['native_sha256'].items()):raise ValueError('原生配置漂移')
    native,_,node=create('xhttp',settings,state['certificates'])
    base=next(c for p,c in before.items() if engines(state)[p]['core']=='xray')
    cfg=copy.deepcopy(base);cfg['inbounds']=[native];cfg.pop('api',None)
    from reality_compat import xray_targets
    cfg=xray_targets({str(CONFIG):cfg})[str(CONFIG)]
    after={**before,str(CONFIG):cfg};updated=copy.deepcopy(state)
    updated['engines']={**engines(state),str(CONFIG):{'core':'xray','service':SERVICE}}
    updated['protocols']['xhttp']=settings
    updated['bindings']['xhttp']={'core':'xray','service':SERVICE,'path':str(CONFIG),'tag':native['tag'],'inbound':native,'auxiliary_tags':[]}
    updated['templates']['xhttp']=node
    agent.validate_native(updated,after)
    from listeners import check
    check(before,after)
    body=json.dumps(cfg,indent=2)+'\n'
    unit='[Unit]\nDescription=ArgoSBX XHTTP loopback entrance\nAfter=network-online.target\n[Service]\nExecStart=/root/agsbx/xray run -c '+str(CONFIG)+'\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=65536\n[Install]\nWantedBy=multi-user.target\n'
    updated['native_sha256'][str(CONFIG)]=agent.sha(body)
    j={'settings':settings,'before':state,'after':updated,'config':body,'unit':unit,'ready':False,
       'source_before':agent.TARGET.read_text()}
    save(journal(),j)
    try:
        atomic(CONFIG,body);atomic(UNIT,unit,0o644)
        agent.cmd(['systemctl','daemon-reload']);agent.cmd(['systemctl','enable','--now',SERVICE]);agent.cmd(['systemctl','is-active','--quiet',SERVICE])
        j['ready']=True;save(journal(),j)
    except Exception:recover();raise
    return {'ready':True,'existing_services_restarted':False}

def candidate():
    j=json.loads(journal().read_text())
    if not j['ready']:raise ValueError('XHTTP 未就绪')
    return export(agent.configs(j['after']),j['after'])['proxies'][-1]

def check_source(j):
    current=agent.TARGET.read_text()
    if current!=j['source_before'] and yaml.safe_load(current)!=export(agent.configs(j['after']),j['after']):
        raise ValueError('验收期间订阅源被外部修改')

def commit():
    j=json.loads(journal().read_text());s=agent.load()
    if not j['ready'] or s not in (j['before'],j['after']):raise ValueError('XHTTP 事务状态变化')
    if any(agent.sha(Path(p).read_text())!=h for p,h in j['after']['native_sha256'].items()):raise ValueError('验收期间原生配置变化')
    check_source(j)
    agent.cmd(['systemctl','is-active','--quiet',SERVICE])
    save(agent.STATE,j['after']);result=agent.export_source(_applying=True)
    journal().unlink();return {**result,'committed':True,'existing_services_restarted':False}

def recover():
    if not journal().exists():return {'recovered':False}
    j=json.loads(journal().read_text())
    if agent.load() not in (j['before'],j['after']):raise ValueError('登记状态被外部修改')
    for p,expected in [(CONFIG,j['config']),(UNIT,j['unit'])]:
        if p.exists() and p.read_text()!=expected:raise ValueError('新增 XHTTP 文件被外部修改')
    check_source(j)
    agent.cmd(['systemctl','disable','--now',SERVICE]) if UNIT.exists() else None
    CONFIG.unlink(missing_ok=True);UNIT.unlink(missing_ok=True);agent.cmd(['systemctl','daemon-reload'])
    save(agent.STATE,j['before']);agent.export_source(_applying=True);journal().unlink()
    return {'recovered':True,'existing_services_restarted':False}
