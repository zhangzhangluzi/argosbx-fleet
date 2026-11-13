"""CI-only real compiler, Caddy route and systemd unit acceptance."""
import json
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ad_rules
import ad_setup
import country_routes

subprocess.run(['systemd-analyze', 'verify', *[str(ROOT/'systemd'/name) for name in ad_setup.UNITS]],
               check=True, capture_output=True)
with tempfile.TemporaryDirectory(prefix='fleet-native-ad-') as directory:
    root = Path(directory)
    compiler = root/'tools/mihomo-1.19.33'
    ad_setup.DEFAULT_COMPILER = compiler
    ad_setup.install_compiler(compiler)
    domains = ('.applovin.com\n.doubleclick.net\n.google-analytics.com\n'
               'pixel.facebook.com\nanalytics.tiktok.com\napi.appsflyersdk.com\n' + '\n'.join(ad_rules.EXTRA_ADS) + '\n')
    snapshot = ad_rules.compile_snapshot('1'*40, domains, compiler)
    assert snapshot['domain_count'] == len(domains.splitlines())
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    ads = root/'ads'
    ads.mkdir()
    (ads/'ads-fixture.mrs').write_bytes(b'fixture-ad-rules')
    config = '''{
 admin off
 auto_https off
}
http://127.0.0.1:PORT {
 # BEGIN TI UNIFIED SUBSCRIPTION
 @subscription path /s/fixture
 handle @subscription {
  respond "fixture-subscription" 200
 }
 # END TI UNIFIED SUBSCRIPTION
 handle {
  respond "not found" 404
 }
}
'''.replace('PORT', str(port))
    config = country_routes.ad_render_main(config).replace('/srv/argosbx/ad-rules', str(ads))
    config_path = root/'Caddyfile'
    config_path.write_text(config)
    subprocess.run(['/usr/local/bin/caddy', 'validate', '--config', str(config_path), '--adapter', 'caddyfile'],
                   check=True, capture_output=True)
    proc = subprocess.Popen(['/usr/local/bin/caddy', 'run', '--config', str(config_path), '--adapter', 'caddyfile'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f'http://127.0.0.1:{port}'
        for attempt in range(30):
            try:
                with urllib.request.urlopen(base+'/s/fixture', timeout=2) as response:
                    assert response.read() == b'fixture-subscription'
                break
            except (OSError, urllib.error.URLError):
                if attempt == 29:
                    raise
                time.sleep(0.2)
        with urllib.request.urlopen(base+'/rules/ad/ads-fixture.mrs', timeout=2) as response:
            assert response.read() == b'fixture-ad-rules'
        try:
            urllib.request.urlopen(base+'/outside', timeout=2)
            raise AssertionError('unexpected route')
        except urllib.error.HTTPError as error:
            assert error.code == 404
    finally:
        proc.terminate()
        proc.wait(timeout=10)
print(json.dumps({'systemd_units': 'validated', 'compiler': 'validated', 'caddy_routes': 'validated'}))
