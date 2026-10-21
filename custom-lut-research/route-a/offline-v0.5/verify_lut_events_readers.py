"""Central native-entry leases, external callers and internal reapply. Offline only."""
import json,struct
from pathlib import Path
from unicorn import UC_MEM_READ
from unicorn import arm_const as ar
import build_lut_events_cp as build
import verify_lut_native_reader as native
import verify_lut_events_integration as integration
v=native.v;own=native.own

class Readers(native.Native):
    def __init__(self,*args,**kwargs):
        self.external=False;self.sources=[];self.native_bodies=[];self.external_results=[]
        super().__init__(*args,**kwargs)
    def memory(self,u,access,address,size,value,unused):
        if access==UC_MEM_READ and self.external and own.CTX+0x300<=address<own.CTX+0x340:
            assert self.bits(),('descriptor read without parent lease',hex(u.reg_read(ar.UC_ARM_REG_PC)))
            self.sources.append(address)
        super().memory(u,access,address,size,value,unused)
    def code(self,u,pc,size,unused):
        if pc in (0x4e8774,0x54e164,0x54e3a0,0xb799e8,0xb79abc):
            self.native_bodies.append((pc,self.bits()))
            assert self.bits()
        if pc==0x6fd56a:
            p=v.RAM+0xb000;table=v.RAM+0xb100
            v.put(u,p,table);v.put(u,table,v.STOP+0x400|1);self.ret(p);return
        if pc in (0x6fbd1e,0x6fbd56):self.ret();return
        if pc==v.STOP+0x400:
            assert u.reg_read(v.reg(1))==11 and u.reg_read(v.reg(3))==8
            self.external_results.append(v.word(u,u.reg_read(v.reg(2))+4));self.ret();return
        if 0x6f492e<=pc<0x6f499a:return
        if 0x6f5d84<=pc<0x6f5e5c:return
        if pc in (0xb799de,0xb79ab4):return  # patched entry may include literal words
        super().code(u,pc,size,unused)
    def external_call(self,art=False):
        # The two real callers build descriptors from incoming arguments.
        v.put(self.u,v.SP,48000)
        if art:
            v.put(self.u,v.SP+8,0x7008000);v.put(self.u,v.SP+12,0);v.put(self.u,v.SP+16,124)
        return self.call(0x6f5de6 if art else 0x6f5d84,own.OWNER,0,0x7000000,0)

def main():
    cp,code,r=build.make();flows=[];external=[];constructors=[];blocked=[]
    for site in native.SITES:
        for art in (False,True):
            n=Readers(cp,code,r,site=site,art=art);n.open();n.invoke();n.invoke()
            assert [struct.unpack_from('<I',m)[0] for m in n.queued]==([1,3,2] if art else [1,2])
            assert n.bits().bit_count()==(2 if art else 1)
            assert n.request()==1
            assert n.work(cp,code).results==[0]*len(n.queued)
            assert not n.bits() and n.request()==0
            flows.append({'site':hex(site),'art':art,'central_context_and_loader_and_constructor_executed':True})
    for art in (False,True):
        n=Readers(cp,code,r);n.open();n.invoke();n.external=True
        assert n.external_call(art)==0
        assert [struct.unpack_from('<I',m)[0] for m in n.queued]==([1,3,2] if art else [1,2])
        assert n.bits().bit_count()==(2 if art else 1) and n.request()==1
        assert n.work(cp,code).results==[0]*len(n.queued)
        assert not n.bits() and n.request()==0
        external.append({'caller':hex(0x6f5de6 if art else 0x6f5d84),'art':art,'native_body_and_queued_children':True})
    for entry,length in ((0xb799de,48000),(0xb79ab4,124)):
        n=Readers(cp,code,r);n.open();pointer=own.CTX+0x300
        n.u.mem_write(pointer,struct.pack('<II',0x7100000,length));n.external=True
        assert n.call(entry,4,pointer,0)==0
        assert n.sources and n.bits().bit_count()==1 and n.request()==1
        assert n.work(cp,code).results==[0] and n.request()==0
        constructors.append({'entry':hex(entry),'external_descriptor_read_after_lease':True})
    for entry in (0x4e876c,0x54e15c,0x54e398,0xb799de,0xb79ab4):
        for reason in ('closed','writer','invalid','fault','full'):
            n=Readers(cp,code,r);pointer=own.CTX+0x300
            n.u.mem_write(pointer,struct.pack('<III',0x7000000,0,48000))
            n.open()
            if reason=='closed':v.put(n.u,native.B.component.GATE,0x80000000)
            if reason=='writer':assert n.request()==0
            elif reason=='invalid':v.put(n.u,native.B.component.GATE,0x40000000)
            elif reason=='fault':v.put(n.u,native.B.component.GATE,0x20000000)
            elif reason=='full':assert all(n.core('lh_cp_reader_begin') for _ in range(29))
            n.external=True;before=n.bits()
            if entry==0x4e876c:n.call(entry,own.OWNER,own.CTX)
            elif entry==0x54e15c:n.call(entry,pointer,1,0,own.PTR)
            elif entry==0x54e398:
                v.put(n.u,v.SP,own.PTR);n.call(entry,pointer,pointer,1,0)
            else:n.call(entry,4,pointer,0)
            assert not n.sources and not n.native_bodies and not n.queued and n.bits()==before
            blocked.append({'entry':hex(entry),'reason':reason,'no_native_source_read':True})
    stale=[];injections=[]
    for index in range(24):
        n=Readers(cp,code,r);n.open()
        v.put(n.u,v.G+0x68+4*index,v.word(n.u,v.G+0x68+4*index)^1)
        n.invoke()
        assert not n.native_bodies and not n.queued and not n.bits()
        stale.append(index)
    for at in (0x54e184,0xb79a34):
        n=Readers(cp,code,r,probe=at);n.open();n.invoke()
        assert n.external_call(False)==0xffff
        assert len(n.probes)==1 and not n.queued and not n.bits() and n.request()==0
        injections.append({'pc':hex(at),'writer_busy_until_parent_end':True,'new_children_rejected_after_close':True})
    class Reapply(integration.SessionIPC):
        reapplying=False
        def code(self,u,pc,size,unused):
            if self.reapplying:
                if pc==0x35c54c or 0x35ced4<=pc<0x35cf4c:return
                assert pc!=0x35c554,'internal reapply must never run native mapping/publication'
            super().code(u,pc,size,unused)
    raw,arx=integration.build.make();bundle=integration.cp_bundle()
    peer=Reapply(bundle);host=integration.Owner(raw,arx,peer);assert host.execute_task()==0
    packet=next(p[32:] for p in reversed(host.protocol) if len(p)==128);addr=integration.ipc.AREA+0xe000
    peer.u.mem_write(addr,packet);peer.reapplying=True
    before=bytes(peer.u.mem_read(v.G+0x68,96));maps=list(peer.mapping_calls)
    assert peer.call(0x35ced4,0x4155,addr)==1
    assert bytes(peer.u.mem_read(v.G+0x68,96))==before and peer.mapping_calls==maps
    bad=bytearray(packet);bad[8]^=1;peer.u.mem_write(addr,bytes(bad))
    assert peer.call(0x35ced4,0x4155,addr)==0
    assert bytes(peer.u.mem_read(v.G+0x68,96))==before and peer.mapping_calls==maps
    peer.u.mem_write(addr,packet)
    wire=bytearray(next(p[:32] for p in reversed(host.protocol) if len(p)==128))
    struct.pack_into('<I',wire,4,2);wire[14]=1;struct.pack_into('<I',wire,24,v.word(peer.u,v.G+0xc0))
    peer.u.mem_write(native.INPUT,bytes(wire))
    assert peer.core('lh_cp_request',native.INPUT,32,native.OUTPUT)==2
    assert peer.call(0x35ced4,0x4155,addr)==0
    assert bytes(peer.u.mem_read(v.G+0x68,96))==before and peer.mapping_calls==maps
    report={'status':'CENTRAL_READER_ENTRIES_VERIFIED_NOT_FLASHABLE','camera_io':False,
            'cp_sha256':build.b.sha(cp),'recipe_sha256':build.b.sha((build.OUT/'recipe.json').read_bytes()),
            'internal_reapply':{'native_indirect_dispatch':True,'confirmed_duplicate_noop':True,'changed_and_held_rejected':True},
            'stale_descriptor_words':stale,'writer_injections':injections,
            'flows':flows,'external_callers':external,'direct_constructors':constructors,'blocked':blocked,
            'source_sha256':{name:build.b.sha((build.b.HERE/name).read_bytes()) for name in (Path(__file__).name,'verify_lut_native_reader.py','verify_lut_reader_placement.py','verify_resource_release.py','verify_lut_events_integration.py','verify_lut_ownership.py','verify_lut_dma_worker.py','verify_queue_completion.py','verify_lut_cp_publication.py','verify_lut_cp_ingress.py')},
            'limitations':['Physical DMA and OS are fixtures. External input ownership/intent is not established by a reader lease.',
                'A closed/invalid/faulted or full core rejects external LUT loaders too. Pre-HELLO readers remain allowed and retain their leases through HELLO.',
                'Function-entry guards cover these native functions; arbitrary unrelated memory reads remain outside the proof.']}
    (build.OUT/'reader-verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'flows':len(flows),'external':len(external),'constructors':len(constructors),'blocked':len(blocked)}))
if __name__=='__main__':main()
