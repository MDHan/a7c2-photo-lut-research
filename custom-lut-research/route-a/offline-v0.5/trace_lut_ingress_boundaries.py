"""Read-only external-source and native CP dispatch boundary inventory."""
import json
import struct
import sys
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
import build as b
sys.path.insert(0,str(b.HERE.parents[1]))
from inspect_current_firmware import direct_thumb_calls


def main():
    raw=(b.HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    assert b.sha(raw)=='48ff01e346ac74e78b61f811725c0bd95ab2712938b55ad607a5b2f54a3bf4e1'
    record=struct.unpack_from('<5I',raw,0x10fc428-b.CP_DELTA)
    assert record==(0x4155,0x35c54d,1,0,0x8db6a1)
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    ranges=[('object_loader',0x6fb03c,0x6fb1de),('regular_test_buffer',0xb7acac,0xb7af10),
            ('art_test_buffer',0xb7b524,0xb7b594),('message_dispatch',0x35cf70,0x35d090),
            ('internal_reapply',0x35ced4,0x35cf48),('native_publish',0x35c54c,0x35c694),
            ('receive_worker',0x4b3a7c,0x4b3b40),('local_copy',0x4b3b74,0x4b3bd4),
            ('reply_copy',0x4b3c48,0x4b3cca),('allocation_length_store',0x565722,0x5657a2),
            ('message_length_helper',0xbec28e,0xbec2a0)]
    listing=[];records=[]
    for name,start,end in ranges:
        data=raw[start-b.CP_DELTA:end-b.CP_DELTA]
        records.append({'name':name,'start':hex(start),'end':hex(end),'sha256':b.sha(data)})
        listing.append(name+'\n'+'\n'.join(f'{i.address:08x} {i.mnemonic:10} {i.op_str}'
                                          for i in decoder.disasm(data,start)))
    out=b.HERE/'lifecycle-dev/ingress-boundaries'
    out.mkdir(exist_ok=True)
    (out/'native-slices.txt').write_text('\n\n'.join(listing)+'\n')
    report={'status':'STATIC_BOUNDARY_INVENTORY_NOT_RUNTIME_COVERAGE','camera_io':False,
            'cp_sha256':b.sha(raw),'source_sha256':b.sha(Path(__file__).read_bytes()),
            'ranges':records,'native_4155_record':[hex(x) for x in record],
            'direct_calls':direct_thumb_calls(raw,[0x6f5d84,0x6f5de6,0x35cf70,0x35c54c]),
            'findings':['Object loader obtains descriptor via vtable slot +0x208, and passes fields to external loader wrappers; backing ownership/lifetime still unknown.',
                        'Two argument-parsing test paths copy static LUT data into fixed CP buffers at 0x25f7b78 and 0x2603ec8 before constructing type-1/type-3 messages.',
                        'The 4155 table points at native 0x35c54d; normal dispatch 0x35cf70 and internal reapply 0x35ced4 both call the table handler indirectly.',
                        'Native publication itself does not send a handoff acknowledgement; a separate ingress adapter is required.',
                        'Native allocation stores requested length at header+0x10, returns header+0x18; bec28e reads payload-8, not the rounded allocation capacity.',
                        '4b3b74 preserves its r2 length through 512b24 to allocation, copies that length, then enqueues; the length is not discarded.',
                        '4b3c48 allocates and copies the reply before enqueue; the receive worker unlocks and frees the input after dispatch. Execution evidence is in cp-ingress-build/verification.json.',
                        'Physical AP transport ingress, formal bridge placement and session initialization remain unverified.'],
            'limitations':['Static direct-call and disassembly evidence only; no complete CFG, physical alias exclusion or normal-mode reachability proof.',
                           'External buffers are not declared safe or excluded from the lifecycle requirement based on their different apparent addresses.']}
    (out/'inventory.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'slices':len(ranges),'output':str(out)}))


if __name__=='__main__':main()
