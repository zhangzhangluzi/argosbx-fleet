#!/usr/bin/env python3
"""Verify and install maintenance code; never restart data-plane services."""
import argparse,hashlib,json,os,re,shutil,tarfile,tempfile
from pathlib import Path

def install(archive,expected,destination):
    archive=Path(archive);destination=Path(destination)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected:raise ValueError('Release archive SHA256 mismatch')
    destination.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.install-',dir=destination) as tmp:
        tmp=Path(tmp)
        with tarfile.open(archive) as t:
            members=t.getmembers()
            if len(members)>100 or sum(m.size for m in members)>4*1024*1024:raise ValueError('Unexpected release size')
            if any(not m.isfile() or m.name.startswith('/') or '..' in Path(m.name).parts for m in members):raise ValueError('Unsafe archive member')
            for m in members:
                p=tmp/m.name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(t.extractfile(m).read())
        manifest=json.loads((tmp/'manifest.json').read_text());version=manifest['version']
        if not re.fullmatch(r'v\d+\.\d+\.\d+',version):raise ValueError('Invalid release version')
        files=manifest['files']
        if {str(p.relative_to(tmp)) for p in tmp.rglob('*') if p.is_file()}!=set(files)|{'manifest.json'}:raise ValueError('Unexpected release contents')
        for name,digest in files.items():
            if hashlib.sha256((tmp/name).read_bytes()).hexdigest()!=digest:raise ValueError('Release file checksum mismatch')
        target=destination/version
        if target.exists():
            if (target/'manifest.json').read_bytes()!=(tmp/'manifest.json').read_bytes():raise ValueError('Immutable version already exists with different content')
            if any(not (target/name).is_file() or (target/name).is_symlink() or hashlib.sha256((target/name).read_bytes()).hexdigest()!=digest for name,digest in files.items()):
                raise ValueError('Installed release file checksum mismatch; current was not changed')
        else:shutil.copytree(tmp,target)
        link=destination/'current.next';link.unlink(missing_ok=True);link.symlink_to(version);os.replace(link,destination/'current')
    return {'installed':version,'service_restarts':0}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('archive');p.add_argument('--sha256',required=True);p.add_argument('--destination',default='/opt/argosbx-fleet');a=p.parse_args()
    print(json.dumps(install(a.archive,a.sha256,a.destination)))
