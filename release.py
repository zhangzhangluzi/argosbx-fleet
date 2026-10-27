#!/usr/bin/env python3
"""Allowlisted, reproducible source release; excludes inventory and local state."""
import argparse,hashlib,io,json,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
FILES=['stash-compat.js','xhttp.py','routing_policy.py','ech.py','country_routes.py','probe.py','acceptance.py','listeners.py','inbounds.py','bootstrap.py','onboard.py','tunnels.py','binaries.json','lease.py','agent.py','domains.py','dns_policy.py','fleet.py','fleetctl.py','generate.py','publication.py','protocols.py','servers.py','storage.py','release.py','install.py','README.md','LICENSE','versions.json','ech-policy.js','region-processor.js','flclash-response-transformer.js']

FILES += ['udp_buffers.py','diagnostics.py','certificates.py','cf_audit.py']

def package(destination):
    manifest=json.loads((ROOT/'versions.json').read_text());files=FILES+[str(p.relative_to(ROOT)) for p in sorted((ROOT/'templates').glob('*'))]
    hashes={f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in files}
    manifest['files']=hashes;destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
    name='argosbx-fleet-'+manifest['version']+'.tar.gz';out=destination/name
    with tarfile.open(out,'w:gz') as t:
        for name,body in [(f,(ROOT/f).read_bytes()) for f in files]+[('manifest.json',(json.dumps(manifest,indent=2)+'\n').encode())]:
            info=tarfile.TarInfo(name);info.size=len(body);info.mode=0o644;info.mtime=0;t.addfile(info,io.BytesIO(body))
    (destination/'SHA256SUMS').write_text(hashlib.sha256(out.read_bytes()).hexdigest()+'  '+out.name+'\n')
    return str(out)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('destination');print(package(p.parse_args().destination))
