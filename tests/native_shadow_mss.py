"""Linux CI: verify the actual nft rule inside a disposable network namespace."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]

def run(args,body=None):
    return subprocess.run(args,input=body,text=True,capture_output=True,timeout=15)

def inside():
    sys.path.insert(0,str(ROOT))
    import subscription_mss as mss
    for profile, port, other_table in (('shadowtls',2448,'argosbx_anytls_mss'),('anytls',2447,'argosbx_shadow_mss')):
        mss.select_profile(profile)
        rule=mss.RULE_SOURCE.read_text()
        assert mss.PORT==port
        assert run(['nft','-c','-f','-'],rule).returncode==0
        assert run(['nft','-f','-'],rule).returncode==0
        try:
            actual=json.loads(run(['nft','-j','list','table','ip',mss.TABLE]).stdout)
            assert mss.valid_table(actual)
            assert run(['nft','list','table','ip','argosbx_sub_mss']).returncode!=0
            assert run(['nft','list','table','ip',other_table]).returncode!=0
            entry=next(x['rule'] for x in actual['nftables'] if 'rule' in x)
            entry['expr'][1]['match']['right']=443
            assert not mss.valid_table(actual)
        finally:
            assert run(['nft','delete','table','ip',mss.TABLE]).returncode==0
    print(json.dumps({'profiles':['shadowtls','anytls'],'native_rules_valid':True,'wrong_port_rejected':True}))

if __name__=='__main__':
    assert sys.platform=='linux' and os.geteuid()==0
    if '--inside' in sys.argv:inside()
    else:
        p=run(['unshare','-n','--',sys.executable,'-B',str(Path(__file__).resolve()),'--inside'])
        if p.returncode:raise RuntimeError('isolated native validation failed: '+p.stderr[-500:])
        print(p.stdout.strip())
