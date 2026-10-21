"""Photo tracker reuse after notification return, with explicit OS/ISP fixtures."""
import concurrent.futures
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import struct
import subprocess
import threading

import build_reusable_entry as build
import verify_tracked_entry as old
import verify_vfx_completion as native
import verify_lut_storage as boot
import verify_release_retry as retry

v=old.v
HERE=Path(__file__).resolve().parent


class Core(native.Completion):
    def __init__(self, cp, layout):
        self.layout=layout
        super().__init__(cp)

    def code(self,u,pc,size,unused):
        start=self.layout['addresses']['entry']
        if start<=pc<start+self.layout['payload_size']:return
        super().code(u,pc,size,unused)

    def core(self,name,*args):
        m=self.layout
        return self.call(m['addresses']['core']+(m['symbols']['core'][name]&~1),*args)


class Photo(old.Photo):
    def __init__(self,*args,**kwargs):
        self.probe=False
        self.probe_active=False
        self.probe_results=[]
        self.notice_states=[]
        super().__init__(*args,**kwargs)

    def code(self,u,pc,size,unused):
        if pc==old.TRAMP and self.probe_active:
            self.probe_results.append(u.reg_read(v.reg(0)))
            self.probe_active=False
        callback_start=self.m['addresses']['callbacks']
        callback_end=callback_start+self.m['sizes']['callbacks']
        caller=u.reg_read(old.ar.UC_ARM_REG_LR)&~1
        if pc==0x5e9a7c and callback_start<=caller<callback_end:
            state=v.word(u,self.cell)
            self.notice_states.append(state)
            assert state&0xf00  # notification is still in flight
            if self.probe:
                self.probe=False;self.probe_active=True
                address=self.m['addresses']['core']+self.m['symbols']['core']['pll_begin']
                self.inject([(address,(self.cell,15))],
                    lambda:native.Completion.code(self,u,pc,size,unused))
                return
        super().code(u,pc,size,unused)

    def check_descriptors(self,tag):
        count,_=old.mapping(self.kind)
        for i,raw in enumerate(v.RAW):
            now=bytearray(self.u.mem_read(raw,0x320));before=self.original[i]
            if i<count and self.mask&(1<<i):
                assert v.word(self.u,raw+0x234)==1
                assert v.word(self.u,raw+0x318)==tag
                callback=self.m['addresses']['callbacks']+self.m['symbols']['callbacks']['photo_context'+str(self.context)]
                assert v.word(self.u,raw+0x31c)==callback
                for off in (0x234,0x318,0x31c):now[off:off+4]=before[off:off+4]
            assert bytes(now)==before

    def prepare_next(self):
        # Model the next native descriptor construction; never touch the cell.
        for i,raw in enumerate(v.RAW):self.u.mem_write(raw,self.original[i])
        self.flags[0x32+self.context]=0
        self.submissions.clear()


def core_cases(cp,m):
    n=Core(cp,m);cell=old.storage.CELLS[0]
    v.put(n.u,cell,0x80)
    cycles=0
    for order in itertools.permutations(range(6)):
        tag=n.core('pll_begin',cell,15)
        assert tag==((cycles+1)<<12)|2
        for index,event in enumerate(order):
            assert n.core('pll_begin',cell,15)==0
            if event<4:
                channel=event+3
                assert n.core('pll_callback_claim',cell,tag,channel)==1
                assert n.core('pll_callback_claim',cell,tag,channel)==0
                assert n.core('pll_begin',cell,15)==0
                assert n.core('pll_callback_finish',cell,tag,channel,0)==1
                assert n.core('pll_callback_claim',cell,tag,channel)==0
                assert n.core('pll_callback_finish',cell,tag,channel,0)==0
            else:
                name='pll_load_complete' if event==4 else 'pll_submit_complete'
                assert n.core(name,cell,tag,1)==1
            if index<5:assert n.core('pll_begin',cell,15)==0
        assert v.word(n.u,cell)==tag&0xfffff000
        cycles+=1
    # Fault arriving during an already claimed callback cannot be cleared.
    v.put(n.u,cell,0x80)
    tag=n.core('pll_begin',cell,1)
    assert n.core('pll_callback_claim',cell,tag,3)==1
    n.core('pll_fault',cell,tag)
    assert n.core('pll_callback_finish',cell,tag,3,0)==1
    assert v.word(n.u,cell)&0x40 and n.core('pll_begin',cell,1)==0
    for word in (0,0xfffff000,0xfffff080):
        v.put(n.u,cell,word)
        assert n.core('pll_begin',cell,1)==0
    for bad in (0,2,0x102,0x1001,0x1102):
        v.put(n.u,cell,0x103f)
        assert n.core('pll_callback_claim',cell,bad,3)==0
        assert n.core('pll_callback_finish',cell,bad,3,0)==0
    return cycles


def notification_equivalence(cp,m):
    cases=0
    for context,ch,error,signal in itertools.product((0,1),range(3,7),(0,7),(0,-18)):
        a=native.Completion(cp)
        a.signal_result=signal
        a.call(0xb1920a+context*12,error,0x12345678,ch)
        n=Core(cp,m);n.signal_result=signal;cell=old.storage.CELLS[context]
        v.put(n.u,cell,0x80)
        tag=n.core('pll_begin',cell,1<<(ch-3))
        n.core('pll_load_complete',cell,tag,1);n.core('pll_submit_complete',cell,tag,1)
        callback=m['addresses']['callbacks']+m['symbols']['callbacks']['photo_context'+str(context)]
        n.call(callback,error,0x12345678,ch,tag)
        assert n.timeline==a.timeline,(context,ch,error,signal,n.timeline,a.timeline)
        assert n.flags==a.flags
        assert bool(v.word(n.u,cell)&0x40)==bool(error or signal)
        assert not v.word(n.u,cell)&0xf00
        before=v.word(n.u,cell);timeline=list(n.timeline)
        n.call(callback,error,0x12345678,ch,tag)
        assert v.word(n.u,cell)==before and n.timeline==timeline
        cases+=1
    return cases


def concurrent_cases():
    lib=build.OUT/'completion-host.dylib'
    command=['/usr/bin/clang','-dynamiclib','-O2','-Wall','-Wextra','-Werror',
             str(HERE/'photo_lut_completion.c'),'-o',str(lib)]
    subprocess.run(command,check=True,capture_output=True)
    dll=ctypes.CDLL(str(lib))
    for name,count in [('pll_begin',2),('pll_load_complete',3),('pll_submit_complete',3),
                       ('pll_callback_claim',3),('pll_callback_finish',4)]:
        f=getattr(dll,name);f.restype=ctypes.c_uint
        f.argtypes=[ctypes.POINTER(ctypes.c_uint)]+[ctypes.c_uint]*(count-1)
    for case in range(64):
        cell=ctypes.c_uint(0x80);p=ctypes.byref(cell)
        tag=dll.pll_begin(p,15);assert tag==0x1002
        claimed=threading.Barrier(5);finish=threading.Event()
        fail=case%8==0
        def callback(ch):
            assert dll.pll_callback_claim(p,tag,ch)==1
            claimed.wait(timeout=10);assert finish.wait(10)
            assert dll.pll_callback_finish(p,tag,ch,int(fail and ch==3))==1
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            jobs=[pool.submit(callback,ch) for ch in range(3,7)]
            jobs += [pool.submit(dll.pll_load_complete,p,tag,1),
                     pool.submit(dll.pll_submit_complete,p,tag,1)]
            claimed.wait(timeout=10)
            assert dll.pll_begin(p,15)==0
            for ch in range(3,7):assert dll.pll_callback_claim(p,tag,ch)==0
            finish.set()
            for job in jobs:job.result(timeout=10)
        assert not cell.value&0xf00
        assert dll.pll_begin(p,15)==(0 if fail else 0x2002)
    return {'epochs':64,'notification_failure_epochs':8,'command':command,
            'scope':'host CPU atomics and threads; not CP interrupt scheduling'}


def main():
    cp,m=build.make()
    permutations=core_cases(cp,m)
    equivalent=notification_equivalence(cp,m)
    threads=concurrent_cases()
    cases=[]
    for context,kind in itertools.product((0,1),range(3,10)):
        count,shift=old.mapping(kind)
        for mask in range(1,1<<count):
            n=Photo(cp,m,context,kind,mask)
            callback=m['addresses']['callbacks']+m['symbols']['callbacks']['photo_context'+str(context)]
            for epoch in (1,2,3):
                assert n.run()==(0x48c790,0)
                n.check_descriptors(epoch*0x1000|2)
                assert v.word(n.u,n.cell)==epoch*0x1000|(mask<<shift)
                if epoch==1:n.probe=True
                n.finish_vfx()
                assert v.word(n.u,n.cell)==epoch*0x1000
                before=list(n.timeline)
                n.call(callback,0,0x12345678,shift+3,epoch*0x1000|2)
                assert n.timeline==before  # duplicate must not signal again
                n.prepare_next()
                if epoch==2:
                    n.call(callback,0,0x12345678,shift+3,0x1002)
                    assert v.word(n.u,n.cell)==0x2000 and n.flags[0x32+context]==0
            assert n.probe_results==[0]
            cases.append({'context':context,'kind':kind,'mask':mask,'captures':3,
                          'begin_during_notification_rejected':True})
    errors=[]
    for mode,code in [('async_load',0),('early_callbacks',0),('acquire_failure',2),
                      ('load_submit_failure',2),('load_callback_failure',2),
                      ('timeout',6),('delay_error',7),('settings_change',3),('submit_failure',10)]:
        n=Photo(cp,m,mode=mode)
        result=n.run()
        assert result==((0x48c790,0) if code==0 else (0x48c778,0xc17e0000|code)),(mode,result)
        if code:
            if mode=='submit_failure':n.finish_vfx();assert n.flags[0x32]==0
            assert v.word(n.u,n.cell)&0x40
            n.prepare_next()
            # Avoid entering the original simulated timeout before checking the cell.
            n.u.mem_write(v.PENDING,b'\0')
            assert n.run()==(0x48c778,0xc17e0008)
        else:
            if mode!='early_callbacks':n.finish_vfx()
            assert v.word(n.u,n.cell)==0x1000
        errors.append({'mode':mode,'first_result':[hex(x) for x in result]})
    n=Photo(cp,m);assert n.run()==(0x48c790,0)
    n.signal_result=-18;n.finish_vfx()
    assert v.word(n.u,n.cell)&0x40 and not n.flags[0x32]
    n.prepare_next();assert n.run()==(0x48c778,0xc17e0008)

    frozen=(HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    mappings=[]
    for mode in (0,1):
        a,ab,_=boot.tables(frozen,mode);z,zb,info=boot.tables(cp,mode)
        assert ab==zb and boot.native_memory_ranges(a)==boot.native_memory_ranges(z)
        mappings.append(info)
    # Relocated retry handler still executes through the native caller.
    rn=retry.Retry(cp,m['addresses']['retry'],m['sizes']['retry'],ready=False)
    rn.u.mem_write(v.PENDING,b'\0');v.put(rn.u,retry.owner.USESTATE,1)
    rn.idle_prefix(0,[0]*4);assert v.word(rn.u,retry.owner.USESTATE)==1
    again,repeat=build.make();assert again==cp and repeat==m
    report={'status':'PHOTO_REUSE_OFFLINE_VERIFIED_NOT_READY_TO_FLASH','camera_io':False,
            'in_memory_cp_sha256':m['in_memory_cp_sha256'],'completion_orderings':permutations,
            'native_notification_equivalence_cases':equivalent,'host_concurrency':threads,
            'mapping_cycles':cases,'load_error_cases':errors,'notification_failure_quarantined':True,
            'boot_mappings':mappings,'retry_handler_regression':True,'repeat_build_identical':True,
            'sources':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
                       ('verify_reusable_entry.py','build_reusable_entry.py','verify_tracked_entry.py',
                        'verify_vfx_completion.py','verify_lut_storage.py','verify_release_retry.py')},
            'limitations':['native OS, MMIO, LUT-load and VFX submission fixtures inherited from photo tests',
                           'next-shot descriptors and event consumption are supplied by the test',
                           'no global native LUT reader or AP upload buffer exclusion',
                           'no fault reset, hardware drain, WBI or production installer',
                           'continuous offline calls do not establish real continuous photography']}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'mapping_cycles':len(cases),'captures':3*len(cases),'orders':permutations,
                      'notification_cases':equivalent,'status':report['status']}))


if __name__=='__main__':main()
