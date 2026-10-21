"""Tracked photo callsite through native submit routing and VFX completion.

Hardware acquisition/loading/status and native module validation remain explicit
boundaries. No production release is faked by the tracked photo entry.
"""
import hashlib
import itertools
import json
from pathlib import Path
import struct
from unicorn import arm_const as ar

import build_tracked_entry as build
import verify_vfx_completion as base
import verify_lut_storage as storage_test
import build_lifecycle_storage as storage

v=base.v
HERE=Path(__file__).resolve().parent
TRAMP=v.STOP+0x300
RANGES=[(0x480f28,0x4810a6),(0x4e876c,0x4e8970),(0x4e89f0,0x4e8a40),
        (0x4e8a5c,0x4e8b22),(0xb31a54,0xb31aac),(0x48c740,0x48c74e)]


def mapping(kind):
    return (1,kind-3) if kind<=6 else ((2,0 if kind==7 else 2) if kind<9 else (4,0))


class Photo(base.Completion):
    def __init__(self,cp,m,context=0,kind=9,mask=15,mode='ready'):
        self.m=m;self.booting=False;self.context=context;self.kind=kind;self.mask=mask;self.mode=mode
        self.pending_calls=[];self.suspended=None;self.after_injection=None
        self.submissions=[];self.loads=[];self.delays=0;self.terminal=None
        super().__init__(cp)
        self.cell=storage.CELLS[context]
        self.stage=0x17233f0+context*0xc90
        self.booting=True
        storage_test.cold_init(self.u,True)
        self.booting=False
        self.setup()
        for channel in range(4):self.configure_gate(channel,15)

    def setup(self):
        u=self.u
        for a,val in [(v.G+0xaf8,10),(v.G+0xafc,0),(v.G+0xb00,0),(v.G+0xb04,1),(v.G+0xb08,0),
                      (v.G+0x68,0x7000000),(v.G+0x70,0x7100000),(v.G+0x78,0xbb80),(v.G+0x7c,0x7c),
                      (v.G+0xc0,0x123),(v.G+0x684,17),(v.STATE,2),(v.DESC,9),(v.TOKEN,0x123),
                      (v.RES,0x8833),(v.MODULE+0x24,0x8833),(v.MODULE+0x12c,self.kind)]:v.put(u,a,val)
        u.mem_write(v.PENDING,b'\0')
        u.mem_write(self.stage,struct.pack('<4I',1,0,0,0))
        for i,raw in enumerate(v.RAW):
            u.mem_write(raw,bytes([0x5a+i])*0x320)
            v.put(u,raw+0x1c8,0x10000 if self.mask&(1<<i) else 0)
            v.put(u,raw+0x234,0)
            v.put(u,raw+0x318,2)
            v.put(u,raw+0x31c,0xb1920b+self.context*12)
        self.original=[bytes(u.mem_read(raw,0x320)) for raw in v.RAW]
        if self.mode!='ready':v.put(u,v.STATE,0)
        if self.mode in ('timeout','delay_error','settings_change'):
            v.put(u,v.STATE,2);u.mem_write(v.PENDING,b'\1')
        if self.mode=='non_user':v.put(u,v.G+0xaf8,11)

    def inject(self,calls,after):
        assert self.suspended is None
        self.suspended=self.u.context_save()
        self.pending_calls=list(calls);self.after_injection=after
        self.next_call()

    def next_call(self):
        self.u.context_restore(self.suspended)
        if not self.pending_calls:
            action=self.after_injection;self.suspended=None;self.after_injection=None
            action();return
        pc,args=self.pending_calls.pop(0)
        for i,val in enumerate(args):self.u.reg_write(v.reg(i),val)
        self.u.reg_write(ar.UC_ARM_REG_LR,TRAMP|1)
        self.u.reg_write(ar.UC_ARM_REG_PC,pc|1)

    def code(self,u,pc,size,unused):
        a=[u.reg_read(v.reg(i)) for i in range(4)]
        start=self.m['addresses']['entry'];end=start+self.m['payload_size']
        if self.booting:
            assert 0x60d334<=pc<0x60d374 or 0x61ed00<=pc<0x61ee38 or start<=pc<end,hex(pc)
            return
        if pc==TRAMP:self.next_call();return
        if pc in (0x48c790,0x48c778,0x48c74e):
            self.terminal=pc;u.emu_stop();return
        if start<=pc<end:return
        if pc in (0x47a7c0,0x47b6f8):self.ret();return
        if pc==0x47b074:  # object validation boundary, not claimed executed
            self.ret(1);return
        if pc==0x4810f4:  # upstream ISP parameter update boundary
            self.ret();return
        if pc==0xbb2bca:  # native acquisition boundary
            if self.mode=='acquire_failure':self.ret(1)
            else:v.put(u,v.RES,v.word(u,a[0]));self.ret()
            return
        if pc in (0x54e15c,0x54e398):  # native load driver boundary
            self.loads.append(pc)
            self.ret(1 if self.mode=='load_submit_failure' else 0);return
        if pc==0x5f4144:
            assert a[0]==20;self.delays+=1
            if self.mode=='delay_error':self.ret(-25)
            elif self.mode=='settings_change':v.put(u,v.G+0x684,18);self.ret()
            elif self.loads and self.mode!='timeout':
                self.inject([(0x4e89f0,(1 if self.mode=='load_callback_failure' else 0,))],lambda:self.ret())
            else:self.ret()
            return
        if pc==0x54d9c8:
            sp=u.reg_read(ar.UC_ARM_REG_SP)
            raw=a[1:]+[v.word(u,sp)]
            owner=v.word(u,v.word(u,sp+4))
            assert a[0]==self.stage and owner==0x8833
            self.submissions.append(raw)
            calls=[]
            for channel,pointer in enumerate(raw):
                if pointer:
                    calls.append((0xbb22d8,(channel,pointer+0x318)))
            if self.mode=='early_callbacks':
                calls += [(0xbb34d4,(ch,)) for ch,p in enumerate(raw) if p]
            result=2 if self.mode=='submit_failure' else 0
            self.inject(calls,lambda:self.ret(result))
            return
        if any(lo<=pc<hi for lo,hi in RANGES):return
        super().code(u,pc,size,unused)

    def run(self):
        u=self.u;self.terminal=None
        for r,val in self.saved.items():u.reg_write(r,val)
        for i,val in enumerate((v.SP+0x4c,v.MODULE,v.PARAM,self.stage)):u.reg_write(v.reg(i),val)
        u.mem_write(v.SP,struct.pack('<4I',*v.RAW))
        u.reg_write(ar.UC_ARM_REG_SP,v.SP)
        u.emu_start(0x48c741,v.STOP,count=500000)
        assert self.terminal is not None
        assert u.reg_read(ar.UC_ARM_REG_SP)==v.SP
        assert all(u.reg_read(r)==val for r,val in self.saved.items())
        assert not any(self.locks.values())
        return self.terminal,v.word(u,v.SP+0x50)

    def finish_vfx(self):
        assert self.submissions
        for ch,pointer in enumerate(self.submissions[-1]):
            if pointer:
                self.configure_gate(ch,15)
                self.call(0xbb34d4,ch)

    def descriptor_check(self,tagged):
        count,_=mapping(self.kind)
        for i,raw in enumerate(v.RAW):
            now=bytearray(self.u.mem_read(raw,0x320));old=self.original[i]
            if i<count and self.mask&(1<<i) and tagged:
                assert v.word(self.u,raw+0x234)==1
                assert v.word(self.u,raw+0x318)==0x102
                callback=self.m['addresses']['callbacks']+self.m['symbols']['callbacks']['photo_context'+str(self.context)]
                assert v.word(self.u,raw+0x31c)==callback
                for off in (0x234,0x318,0x31c):now[off:off+4]=old[off:off+4]
            assert bytes(now)==old,(self.kind,self.mask,i)


def main():
    cp,m=build.make();cases=[]
    for context,kind in itertools.product((0,1),range(3,10)):
        count,shift=mapping(kind)
        for mask in range(1,1<<count):
            n=Photo(cp,m,context,kind,mask)
            assert n.run()==(0x48c790,0)
            expected=[0]*4
            for i in range(count):expected[shift+i]=v.RAW[i]
            assert n.submissions==[expected]
            assert v.word(n.u,n.cell)==0x100|(mask<<shift)
            n.descriptor_check(True)
            n.finish_vfx()
            assert v.word(n.u,n.cell)==0x100
            # Original registers callbacks on all module channels; tracked
            # wrapper is only installed on the selected LUT-reading channels.
            assert n.flags[0x32+context] & (mask<<shift<<12)==mask<<shift<<12
            cases.append({'context':context,'module_kind':kind,'raw_mask':mask,
                          'tracked_channel_mask':mask<<shift,'normal_completion_recorded':True})
    errors=[]
    for mode,code in [('async_load',0),('early_callbacks',0),('acquire_failure',2),
                      ('load_submit_failure',2),('load_callback_failure',2),
                      ('timeout',6),('delay_error',7),('settings_change',3),('submit_failure',10)]:
        n=Photo(cp,m,mode=mode)
        terminal,error=n.run()
        if code==0:
            assert (terminal,error)==(0x48c790,0),(mode,terminal,hex(error))
            if mode!='early_callbacks':n.finish_vfx()
            assert v.word(n.u,n.cell)==0x100
            n.descriptor_check(True)
        else:
            assert terminal==0x48c778 and error==0xc17e0000|code,(mode,terminal,hex(error))
            assert v.word(n.u,n.cell)&0x40
            n.descriptor_check(False)
            if mode=='submit_failure':
                n.finish_vfx()
                assert n.flags[0x32]==0 and v.word(n.u,n.cell)&0x40
            else:assert not n.submissions
        if mode=='timeout':assert n.delays==150
        errors.append({'mode':mode,'terminal':hex(terminal),'error':hex(error),
                       'native_load_boundaries':[hex(x) for x in n.loads],
                       'waits':n.delays,'photo_state':hex(v.word(n.u,n.cell))})
    # Reused context has not been released by a real owner; refuse another
    # capture before acquisition, without corrupting the existing epoch.
    n=Photo(cp,m);assert n.run()==(0x48c790,0)
    before=v.word(n.u,n.cell)
    for raw in v.RAW:
        v.put(n.u,raw+0x318,2);v.put(n.u,raw+0x31c,0xb1920b);v.put(n.u,raw+0x234,0)
    n.submissions.clear();assert n.run()==(0x48c778,0xc17e0008)
    assert v.word(n.u,n.cell)==before and not n.submissions
    # Unsupported stage/callback provenance fails before claiming storage.
    for case in ('stage','callback'):
        n=Photo(cp,m)
        if case=='stage':n.stage=v.STAGE
        else:v.put(n.u,v.RAW[0]+0x31c,0xb19217)
        assert n.run()==(0x48c778,0xc17e0009)
        assert v.word(n.u,n.cell)==0x80 and not n.submissions
    n=Photo(cp,m,mode='non_user');assert n.run()==(0x48c790,0)
    assert v.word(n.u,n.cell)==0x80
    n.descriptor_check(False)
    report={'status':'TRACKED_ENTRY_OFFLINE_VERIFIED_NOT_READY_TO_FLASH','camera_io':False,
            'in_memory_cp_sha256':hashlib.sha256(cp).hexdigest(),'mapping_cases':cases,
            'load_and_error_cases':errors,'busy_context_preserved':True,
            'invalid_context_cases':2,'non_user_passthrough':True,
            'test_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'dependencies':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest()
                            for name in ('build_tracked_entry.py','verify_vfx_completion.py','verify_lut_storage.py')},
            'fixtures':['native module validation and upstream ISP parameter update',
                        'LUT acquire/load driver results and OS delay',
                        'VFX hardware submit boundary schedules native callback registration',
                        'hardware output status, OS event flags and locks'],
            'not_completed':['production resource release and fault recovery',
                             'global native readers and shared AP upload ownership',
                             'full native scheduler/ISP/JPEG hardware',
                             'WBI/installer and complete menu lifecycle']}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'mapping_cases':len(cases),'load_and_error_cases':len(errors),
                      'status':report['status']}))


if __name__=='__main__':main()
