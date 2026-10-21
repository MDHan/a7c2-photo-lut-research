"""CP lease machine code and AP/CP paired protocol with native publication.

The coordinator/transport/reader calls are test wiring, not production hooks.
"""
import ctypes
import hashlib
import json
import struct
import subprocess
import threading
from pathlib import Path
import build_lut_handoff_cp as build_cp
import build_lut_handoff_ap as build_ap
from verify_lut_handoff_ap import Core, packet
from verify_shared_buffer_interleaving import Receiver
from verify_upload_guards import Guarded
import verify as v
import verify_lut_storage as boot
from unicorn import arm_const as ar

HERE=build_cp.HERE
CODE,STATE,INPUT,OUTPUT=v.RAM+0x8000,v.RAM+0x1000,v.RAM+0x2000,v.RAM+0x2100


def request(id=1,op=1,generation=17):
    p=bytearray(packet(id=id,op=op,generation=generation));p[0]=5
    return bytes(p)


class Cp(Receiver):
    def __init__(self,cp,code,recipe):
        super().__init__(cp)
        self.recipe=recipe;self.end=CODE+len(code)
        self.u.mem_write(CODE,code);self.u.mem_write(STATE,bytes(148))
    def code(self,u,pc,size,unused):
        if CODE<=pc<getattr(self,'end',CODE):return
        super().code(u,pc,size,unused)
    def call(self,name,*args):
        args=(STATE,*args);u=self.u
        saved={v.reg(i):0x11800000+i for i in range(4,12)}
        for reg,value in saved.items():u.reg_write(reg,value)
        for i,value in enumerate(args[:4]):u.reg_write(v.reg(i),value)
        for i,value in enumerate(args[4:]):v.put(u,v.SP+4*i,value)
        u.reg_write(ar.UC_ARM_REG_SP,v.SP);u.reg_write(ar.UC_ARM_REG_LR,v.STOP|1)
        u.emu_start((CODE+self.recipe['symbols'][name])|1,v.STOP,count=30000)
        assert u.reg_read(ar.UC_ARM_REG_PC)==v.STOP
        assert u.reg_read(ar.UC_ARM_REG_SP)==v.SP
        assert all(u.reg_read(reg)==value for reg,value in saved.items())
        return u.reg_read(v.reg(0))
    def open(self):assert self.call('lh_cp_open',0x1234,0x5678,17)==1
    def req(self,p):
        self.u.mem_write(INPUT,p or b'\0');self.u.mem_write(OUTPUT,b'\xa5'*40)
        result=self.call('lh_cp_request',INPUT,len(p),OUTPUT)
        out=bytes(self.u.mem_read(OUTPUT,32))
        assert self.u.mem_read(OUTPUT+32,8)==b'\xa5'*8
        if result!=2:assert out==b'\xa5'*32
        return result,out
    def published(self,id=1,ok=1,generation=18):
        self.u.mem_write(OUTPUT,b'\xa5'*40)
        result=self.call('lh_cp_published',id,ok,generation,OUTPUT)
        assert self.u.mem_read(OUTPUT+32,8)==b'\xa5'*8
        return result,bytes(self.u.mem_read(OUTPUT,32))
    def gate(self):return v.word(self.u,STATE+4)
    def phase(self):return v.word(self.u,STATE+24)


def reply(h,p,status):
    kind,out=h.req(p);assert kind==2 and out[15]==status,(kind,out.hex())
    return out


def component_cases(cp,code,r):
    results=[]
    h=Cp(cp,code,r)
    # Read leases can precede session setup. Open must not erase them.
    token=h.call('lh_cp_reader_begin');assert token
    h.open();assert h.gate()&0x1fffffff
    assert h.call('lh_cp_open',1,2,33)==0
    reply(h,request(),1);assert h.call('lh_cp_reader_begin')==0
    assert h.call('lh_cp_reader_end',token)==1
    assert h.call('lh_cp_reader_end',token)==0
    reply(h,request(),0);assert h.gate()==0xc0000000
    reply(h,request(),0) # Duplicate grant request is idempotent.
    reply(h,request(id=2),1)
    reply(h,request(op=2,generation=16),2)
    assert h.req(request(op=2))[0]==3 and h.phase()==3
    reply(h,request(op=3),1);assert h.call('lh_cp_reader_begin')==0
    assert h.published(id=2)[0]==1 and h.gate()==0xc0000000
    assert h.published()[0]==2 and h.gate()==0
    reply(h,request(op=2,generation=17),0)
    reply(h,request(op=3),0)
    assert h.call('lh_cp_reader_begin')
    results.append('reader_drain_duplicate_grant_publication_and_wrong_id')
    for grant_first in (False,True):
        h=Cp(cp,code,r);h.open()
        if grant_first:reply(h,request(),0)
        reply(h,request(op=3),0)
        reply(h,request(),2)
        token=h.call('lh_cp_reader_begin')
        assert bool(token)==(not grant_first)
        if token:h.call('lh_cp_reader_end',token)
        assert h.gate()==(0x40000000 if grant_first else 0)
        reply(h,request(id=2),0)
        assert h.req(request(id=2,op=2))[0]==3
        assert h.published(id=2,ok=0)[1][15]==2
        reply(h,request(id=2,op=3),0)
        assert h.gate()==0x40000000 and h.call('lh_cp_reader_begin')==0
        reply(h,request(id=3),0)
        assert h.req(request(id=3,op=2,generation=18))[0]==3
        h.published(id=3);assert h.gate()==0
        results.append({'cancel_before_grant':not grant_first,'invalid_until_full_republish':True})
    h=Cp(cp,code,r);h.open()
    tokens=[h.call('lh_cp_reader_begin') for _ in range(29)]
    assert len(set(tokens))==29 and all(tokens)
    assert h.call('lh_cp_reader_begin')==0
    for token in tokens:assert h.call('lh_cp_reader_end',token)==1
    newer=h.call('lh_cp_reader_begin');assert newer!=tokens[0]
    assert h.call('lh_cp_reader_end',tokens[0])==0
    reply(h,request(),1)
    assert h.call('lh_cp_reader_fault',newer)==1
    assert h.call('lh_cp_reader_end',newer)==0
    reply(h,request(),2);reply(h,request(op=3),0)
    reply(h,request(id=2),2);assert h.call('lh_cp_reader_begin')==0
    results.append('29_slots_duplicate_stale_completion_and_fault_quarantine')
    h=Cp(cp,code,r);h.open()
    for i in range(29):v.put(h.u,STATE+32+i*4,0x07ffffff)
    assert h.call('lh_cp_reader_begin')==0 and h.gate()==0
    results.append('reader_epoch_exhaustion_no_wrap')
    h=Cp(cp,code,r);h.open();v.put(h.u,STATE,1)
    before=bytes(h.u.mem_read(STATE,148));assert h.req(request())[0]==1
    assert bytes(h.u.mem_read(STATE,148))==before
    results.append('request_lock_contention_drops_without_spin')
    malformed=[]
    packets=[request()[:n] for n in range(32)]+[request()+b'\0']
    for offset,value in [(1,1),(12,2),(13,1),(14,0),(14,4),(15,1),(28,1),(4,0)]:
        p=bytearray(request());p[offset]=value;packets.append(bytes(p))
    for p in packets:
        h=Cp(cp,code,r);h.open();before=bytes(h.u.mem_read(STATE,148))
        kind,_=h.req(p)
        assert kind in (0,1) and bytes(h.u.mem_read(STATE,148))==before
        malformed.append({'length':len(p),'packet':p.hex(),'result':kind})
    return results,malformed


def paired(ap,ap_recipe,cp,code,r):
    cases=[]
    manifest=json.loads((HERE/'dev-menu-03/manifest.json').read_text())
    for special,mapping_failure in ((False,False),(True,False),(False,True),(True,True)):
        host=Core(ap,ap_recipe);host.opened()
        class Publication(Cp):
            def code(self,u,pc,size,unused):
                if mapping_failure and pc==0xb44a2c:
                    # The real receiver handles this mapping failure and still
                    # returns 1 / advances generation. It is not publication success.
                    u.reg_write(v.reg(0),1)
                    u.reg_write(ar.UC_ARM_REG_PC,u.reg_read(ar.UC_ARM_REG_LR))
                    return
                super().code(u,pc,size,unused)
        peer=Publication(cp,code,r);peer.open()
        token=peer.call('lh_cp_reader_begin');assert token
        def send():
            assert host.call('lh_ap_request',0x10007000)==32
            return peer.req(bytes(host.u.mem_read(0x10007000,32)))
        kind,p=send();assert kind==2 and p[15]==1;host.receive(p)
        assert host.call('lh_ap_write',1)==0 and peer.call('lh_cp_reader_begin')==0
        peer.call('lh_cp_reader_end',token)
        kind,p=send();assert kind==2 and p[15]==0;host.receive(p)
        assert host.call('lh_ap_write',1)==1
        # Explicit coordinator fixture: this call is not yet inside the upload
        # firmware. File/mapping/interchip services inherit upload fixtures.
        upload=Guarded(ap,manifest,b'\x52'*(48124 if special else 48000),special=special)
        native_message=upload.execute(system=2)
        assert host.call('lh_ap_written',1,1)==1
        kind,_=send();assert kind==3 and peer.call('lh_cp_reader_begin')==0
        peer.receive(native_message) # Actual original 35c54c descriptor receiver.
        generation=v.word(peer.u,v.G+0xc0);assert generation==18
        valid=(v.word(peer.u,v.G+0x78)==48000 and v.word(peer.u,v.G+0x68)!=0)
        assert valid==(not mapping_failure)
        kind,p=peer.published(ok=int(valid),generation=generation);assert kind==2
        host.receive(p)
        if mapping_failure:
            assert host.phase()==7 and peer.call('lh_cp_reader_begin')==0
            assert v.word(peer.u,STATE+28)==generation
            kind,p=send();assert kind==2 and p[15]==0
            host.receive(p)
            assert host.phase()==1 and peer.gate()==0x40000000
        else:
            assert host.phase()==1 and peer.call('lh_cp_reader_begin')
        assert host.call('lh_ap_begin')==2
        cases.append({'special':special,'mapping_failure_fixture':mapping_failure,
                      'native_descriptor_generation':generation,'published_success':valid,
                      'busy_before_reader_end':True,'native_upload_and_receiver_executed':True,
                      'coordinator_is_fixture':True})
    # A lost grant cannot later resurrect an already cancelled lease.
    host=Core(ap,ap_recipe);host.opened();peer=Cp(cp,code,r);peer.open()
    grant=reply(peer,request(generation=0),0)
    assert host.call('lh_ap_cancel',1)==1
    cancelled=reply(peer,request(op=3,generation=0),0)
    host.receive(cancelled);assert host.call('lh_ap_begin')==2
    before=host.snapshot();host.receive(grant);assert host.snapshot()==before
    assert host.call('lh_ap_write',2)==0 and peer.call('lh_cp_reader_begin')==0
    reply(peer,request(),2)
    cases.append({'lost_grant_then_cancel_then_late_grant':'no_write_or_read_permission'})
    return cases


def races():
    out=build_cp.OUT/'cp-handoff-host.dylib'
    subprocess.run(['/usr/bin/clang','-dynamiclib','-O2','-Wall','-Wextra','-Werror',
                    str(HERE/'lut_handoff_cp.c'),'-o',str(out)],check=True,capture_output=True,text=True)
    lib=ctypes.CDLL(str(out))
    class State(ctypes.Structure):_fields_=[('words',ctypes.c_uint32*37)]
    for name,args in [('lh_cp_open',[ctypes.POINTER(State),ctypes.c_uint32,ctypes.c_uint32,ctypes.c_uint32]),
                      ('lh_cp_reader_begin',[ctypes.POINTER(State)]),
                      ('lh_cp_reader_end',[ctypes.POINTER(State),ctypes.c_uint32]),
                      ('lh_cp_request',[ctypes.POINTER(State),ctypes.c_void_p,ctypes.c_uint32,ctypes.c_void_p])]:
        fn=getattr(lib,name);fn.argtypes=args;fn.restype=ctypes.c_uint32
    for mode in ('reader_vs_writer','old_release_vs_new_reader'):
        for attempt in range(64):
            c=State();assert lib.lh_cp_open(ctypes.byref(c),0x1234,0x5678,17)==1
            old=0
            if mode=='old_release_vs_new_reader':
                old=lib.lh_cp_reader_begin(ctypes.byref(c));assert old
                assert lib.lh_cp_reader_end(ctypes.byref(c),old)==1
            start=threading.Barrier(3);results={};errors=[]
            p=ctypes.create_string_buffer(request());outbuf=ctypes.create_string_buffer(32)
            def run(which):
                try:
                    start.wait()
                    if which==0:results[0]=lib.lh_cp_reader_begin(ctypes.byref(c))
                    elif mode=='reader_vs_writer':results[1]=lib.lh_cp_request(ctypes.byref(c),p,32,outbuf)
                    else:results[1]=lib.lh_cp_reader_end(ctypes.byref(c),old)
                except BaseException as error:errors.append(repr(error))
            workers=[threading.Thread(target=run,args=(i,)) for i in (0,1)]
            for worker in workers:worker.start()
            start.wait()
            for worker in workers:worker.join(timeout=5);assert not worker.is_alive()
            assert not errors,errors
            if mode=='reader_vs_writer':
                assert results[1]==2
                assert outbuf.raw[15]==(1 if results[0] else 0)
            else:
                assert results[0] and results[1]==0
                assert lib.lh_cp_request(ctypes.byref(c),p,32,outbuf)==2 and outbuf.raw[15]==1
    return {'reader_writer_races':64,'stale_release_new_reader_races':64,
            'host_library_sha256':hashlib.sha256(out.read_bytes()).hexdigest()}


def placement_scope(cp,r):
    reuse=json.loads((HERE/'lifecycle-dev/reuse-build/recipe.json').read_text())
    payload=(HERE/'lifecycle-dev/reuse-build/composed-payload.bin').read_bytes()
    assert len(payload)==reuse['payload_size']==2592
    record=next(p for p in reuse['patches'] if p['offset']==reuse['addresses']['entry']-0x108000)
    assert bytes.fromhex(record['after'])==payload
    remaining=0xc30000-(reuse['addresses']['entry']+len(payload))
    assert remaining==336 and r['code_bytes']>remaining
    ro=struct.unpack_from('<3I',cp,0x20130)
    rw=struct.unpack_from('<3I',cp,0x2013c)
    bs=struct.unpack_from('<3I',cp,0x20148)
    assert ro[2]+ro[1]==0x10c6b84 and rw[2]+rw[1]==0x1209aa0
    pages=[]
    for mode in (False,True):
        u,_,info=boot.tables(cp,mode);l1=int(info['l1'],16)
        for address in (0x10c6b84,0x1209aa0):
            pde=v.word(u,l1+(address>>20)*4)
            pte=v.word(u,(pde&~1023)+((address>>12)&255)*4)
            assert pte&1
            pages.append({'mode':mode,'address':hex(address),'pte':hex(pte),'execute_never':True})
    state_end=bs[2]+bs[1]+8+r['state_bytes']
    assert state_end==0x1b85ff8 and state_end<0x1b86000
    return {'reuse_payload_bytes':len(payload),'remaining_declared_text_page_bytes':remaining,
            'reuse_recipe_sha256':hashlib.sha256((HERE/'lifecycle-dev/reuse-build/recipe.json').read_bytes()).hexdigest(),
            'reuse_payload_sha256':hashlib.sha256(payload).hexdigest(),
            'cp_component_bytes':r['code_bytes'],'cannot_append_to_current_text_tail':True,
            'ro_padding_bytes':rw[2]-(ro[2]+ro[1]),'rw_padding_bytes':bs[2]-(rw[2]+rw[1]),
            'native_padding_pages':pages,'proposed_state_end':hex(state_end),
            'state_has_not_been_declared_in_a_cp_image':True}


def main():
    code,r=build_cp.make();again,r2=build_cp.make();assert code==again and r==r2
    ap,ap_recipe=build_ap.make()
    cp=(HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    assert hashlib.sha256(cp).hexdigest()=='48ff01e346ac74e78b61f811725c0bd95ab2712938b55ad607a5b2f54a3bf4e1'
    cases,malformed=component_cases(cp,code,r)
    pair=paired(ap,ap_recipe,cp,code,r);concurrent=races()
    placement=placement_scope(cp,r)
    report={'status':'CP_LEASE_AND_PAIRED_PROTOCOL_OFFLINE_VERIFIED_NOT_FLASHABLE','camera_io':False,
            'cp_sha256':hashlib.sha256(cp).hexdigest(),'ap_sha256':ap_recipe['in_memory_ap_sha256'],
            'component_sha256':hashlib.sha256((build_cp.OUT/'component.json').read_bytes()).hexdigest(),
            'ap_recipe_sha256':hashlib.sha256((build_ap.OUT/'recipe.json').read_bytes()).hexdigest(),
            'component_cases':cases,'malformed_cases':malformed,'paired_cases':pair,'concurrency':concurrent,
            'placement_scope':placement,
            'limitations':['CP component runs in emulator scratch memory; no CP image placement or hooks',
                           'native reader admission/completion and private IPC dispatch not wired',
                           'paired coordinator and transport are fixtures, not actual upload integration',
                           'native publication receiver uses mapping fixtures; no real DMA or hardware cache ordering',
                           'session bootstrap, deadlines, WBI and installer remain incomplete'],
            'source_sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
                            ('verify_lut_handoff_cp.py','verify_lut_handoff_ap.py','verify_shared_buffer_interleaving.py',
                             'verify_upload_guards.py','verify_lut_upload.py','verify_menu.py','verify_lut_storage.py')}}
    (build_cp.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'component_cases':len(cases),'malformed_cases':len(malformed),'paired_cases':len(pair),
                      'host_races':128,'status':report['status']}))


if __name__=='__main__':main()
