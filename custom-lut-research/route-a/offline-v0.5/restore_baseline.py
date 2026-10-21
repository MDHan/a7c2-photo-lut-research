"""Restore the exact baseline to NEW LOCAL FILES; never writes a camera."""
import argparse, json
from pathlib import Path
import build

def restore(folder,output):
    m=json.loads((folder/'manifest.json').read_text())
    assert m['inputs']==build.HASHES and set(m['outputs'])==set(build.HASHES)
    restored={}
    for name,spec in m['outputs'].items():
        raw=bytearray((folder/'candidate'/name).read_bytes())
        assert len(raw)==spec['size'] and build.sha(raw)==spec['sha256']
        for p in m['patches']:
            if p['file']!=name:continue
            start=p['offset'];end=start+p['length']
            assert raw[start:end]==bytes.fromhex(p['after'])
            raw[start:end]=bytes.fromhex(p['before'])
        assert build.sha(raw)==build.HASHES[name]
        restored[name]=raw
    output.mkdir(parents=True,exist_ok=False)
    for name,raw in restored.items():(output/name).write_bytes(raw)
    return {name:build.sha(raw) for name,raw in restored.items()}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(json.dumps(restore(a.folder,a.output),indent=2))
