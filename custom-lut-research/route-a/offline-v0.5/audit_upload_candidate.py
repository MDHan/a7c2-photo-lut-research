"""Bind already-executed dev-menu-03 verification reports; never release hardware."""
import json
from pathlib import Path
import build as b
import verify as v

HERE=Path(__file__).resolve().parent
FOLDER=HERE/'dev-menu-03'


def main():
    m=json.loads((FOLDER/'manifest.json').read_text())
    pair={n:row['sha256'] for n,row in m['outputs'].items()}
    structural=v.structural(FOLDER,m)
    for source in m['build_sources']:
        assert b.sha((HERE/source['source']).read_bytes())==source['sha256']
    names=('verification.json','menu-verification.json','dynamic-menu-verification.json',
           'menu-relocation-verification.json','upload-guard-verification.json')
    reports={n:json.loads((FOLDER/n).read_text()) for n in names}
    core=reports['verification.json']; provenance=core['verification_provenance']
    assert core['structural']==structural and provenance['candidate_sha256']==pair
    assert provenance['script_sha256']==b.sha((HERE/'verify.py').read_bytes())
    assert provenance['builder_sha256']==b.sha((HERE/'build.py').read_bytes())
    menu=reports['menu-verification.json']; dynamic=reports['dynamic-menu-verification.json']
    assert menu['candidate_sha256']==dynamic['candidate_sha256']==pair['appFw.so']
    assert menu['script_sha256']==b.sha((HERE/'verify_menu.py').read_bytes())
    assert dynamic['source_sha256']==b.sha((HERE/'verify_dynamic_menu.py').read_bytes())
    reloc=reports['menu-relocation-verification.json']
    assert reloc['sha256']['after']==pair['appFw.so']
    assert reloc['source_sha256']==b.sha((HERE/'verify_rule_relocations.py').read_bytes())
    guards=reports['upload-guard-verification.json']
    assert guards['structural']==structural and guards['rebuild_byte_identical'] and guards['inverse_to_FL23_verified']
    for name,sha in guards['source_hashes'].items():assert b.sha((HERE/name).read_bytes())==sha
    assert all(report['camera_io'] is False for report in reports.values())
    assert len(guards['valid_comparisons'])==32 and len(guards['length_cases'])==36
    assert len(guards['fault_cases'])==9 and len(guards['rebased_length_cases'])==168 and len(guards['rebased_mapping_cases'])==12
    assert dynamic['target_evaluator_changes']==16 and dynamic['other_constraint_comparisons']==10496
    report={'status':'NOT_READY_TO_FLASH','camera_io':False,'candidate':'dev-menu-03',
            'candidate_sha256':pair,'structural':structural,'rebuild_byte_identical':True,
            'local_inverse_patch_verified':True,
            'implemented':['Minimum actual byte coverage before native LUT copy',
                           'MAP_FAILED rejection and one close attempt in LUT mapping caller'],
            'scope':'Valid user LUT messages unchanged in tested still/movie paths. Short user LUT reads rejected in both modes. CP image unchanged.',
            'blockers':['Complete import, edit/delete, still/movie switching and full model/event state unverified.',
                        'Length coverage does not validate imported LUT format or pixel/color correctness.',
                        'Shared buffer overwrite, capture ownership, timeout and resource cleanup unresolved.',
                        'Camera native session/platform, live activation, settings preservation and recovery incomplete.',
                        'No camera boot, menu UI, preview/playback or full-size JPEG validation.'],
            'reports':{name:b.sha((FOLDER/name).read_bytes()) for name in names},
            'audit_source_sha256':b.sha(Path(__file__).read_bytes())}
    (FOLDER/'readiness.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'candidate_sha256':pair,'report_bindings_verified':len(names)}))

if __name__=='__main__':main()
