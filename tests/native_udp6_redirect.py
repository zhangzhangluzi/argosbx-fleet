"""Linux CI: verify the actual IPv6 NAT rule in an isolated network namespace."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
def run(args, body=None):
    return subprocess.run(args, input=body, text=True, capture_output=True, timeout=15)
def inside():
    sys.path.insert(0, str(ROOT))
    import udp6_redirect as redirect
    config = {'address':'2606:4700:4700::1111','port':443,'target_port':2446}
    rule = redirect.render(config).decode()
    assert run(['nft','-c','-f','-'],rule).returncode == 0
    assert run(['nft','-f','-'],rule).returncode == 0
    try:
        actual = json.loads(run(['nft','-j','list','table','ip6',redirect.TABLE]).stdout)
        assert redirect.valid_table(actual, config)
        assert run(['nft','list','table','ip',redirect.TABLE]).returncode != 0
        entry = next(x['rule'] for x in actual['nftables'] if 'rule' in x)
        entry['expr'][1]['match']['right'] = 8443
        assert not redirect.valid_table(actual, config)
    finally:
        assert run(['nft','delete','table','ip6',redirect.TABLE]).returncode == 0
    print(json.dumps({'native_rule_valid':True,'wrong_port_rejected':True,'ipv4_untouched':True}))
if __name__ == '__main__':
    assert sys.platform == 'linux' and os.geteuid() == 0
    if '--inside' in sys.argv: inside()
    else:
        p = run(['unshare','-n','--',sys.executable,'-B',str(Path(__file__).resolve()),'--inside'])
        if p.returncode: raise RuntimeError('isolated validation failed: '+p.stderr[-500:])
        print(p.stdout.strip())
