"""Execute native next-shot callback-field construction before reused entry.

Only the native callback-field fragment runs; other next-shot descriptors and
event consumption remain fixtures. Does not run a whole capture scheduler.
"""
import hashlib
import json
from pathlib import Path
import struct
from unicorn import arm_const as ar
import verify_reusable_entry as reuse

v=reuse.v
HERE=Path(__file__).resolve().parent


class Reconstruct(reuse.Photo):
    def code(self,u,pc,size,unused):
        if 0x48c5a0<=pc<0x48c5ac:return
        super().code(u,pc,size,unused)

    def reconstruct(self,raw):
        u=self.u
        before=bytes(u.mem_read(raw,0x320))
        context=u.context_save()
        u.reg_write(ar.UC_ARM_REG_SP,v.SP)
        u.reg_write(v.reg(5),raw-0x10)
        v.put(u,v.SP+0x38,0xb1920b+self.context*12)
        u.emu_start(0x48c5a1,0x48c5ac,count=4)
        assert u.reg_read(ar.UC_ARM_REG_PC)==0x48c5ac
        after=bytearray(u.mem_read(raw,0x320))
        assert after[0x318]==2
        # Native initialization writes a byte, so an old high tag survives.
        assert after[0x319:0x31c]==before[0x319:0x31c]
        assert v.word(u,raw+0x31c)==0xb1920b+self.context*12
        after[0x318:0x320]=before[0x318:0x320]
        assert bytes(after)==before
        u.context_restore(context)


def main():
    m=json.loads((reuse.build.OUT/'recipe.json').read_text())
    cp=bytearray((HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes())
    assert hashlib.sha256(cp).hexdigest()==m['base_cp_sha256']
    for p in m['patches']:
        off=p['offset'];assert cp[off:off+p['length']]==bytes.fromhex(p['before'])
        cp[off:off+p['length']]=bytes.fromhex(p['after'])
    assert hashlib.sha256(cp).hexdigest()==m['in_memory_cp_sha256']
    cases=[]
    for context in (0,1):
        n=Reconstruct(bytes(cp),m,context=context)
        assert n.run()==(0x48c790,0)
        n.finish_vfx();assert v.word(n.u,n.cell)==0x1000
        for raw in v.RAW:n.reconstruct(raw)
        assert all(v.word(n.u,raw+0x318)==0x1002 for raw in v.RAW)
        n.flags[0x32+context]=0
        n.submissions.clear()
        assert n.run()==(0x48c790,0)
        assert all(v.word(n.u,raw+0x318)==0x2002 for raw in v.RAW)
        n.finish_vfx();assert v.word(n.u,n.cell)==0x2000
        cases.append({'context':context,'native_callback_fields':4,
                      'old_upper_tag_preserved_by_native_byte_store':True,
                      'entry_replaced_full_tag_on_next_capture':True})
    report={'status':'NATIVE_CALLBACK_RECONSTRUCTION_OFFLINE_VERIFIED',
            'cp_sha256':m['in_memory_cp_sha256'],'cases':cases,'camera_io':False,
            'source_sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest()
                             for name in ('verify_callback_reconstruction.py','verify_reusable_entry.py')},
            'limitations':['native callback-field construction fragment only',
                           'OS, hardware and other descriptor construction remain fixtures']}
    (reuse.build.OUT/'callback-reconstruction.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'contexts':2,'native_callback_fields':8,'status':report['status']}))


if __name__=='__main__':main()
