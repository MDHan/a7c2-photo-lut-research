"""Compiled CP receiver owns native publication and completion acknowledgement.

Real AP/CP cores and native upload/publication execute; message delivery,
mapping, source transfer, OS, scheduler and new receiver placement are fixtures.
"""
import json
import struct
from unicorn import UC_MEM_READ,UC_PROT_READ,UC_PROT_EXEC
from unicorn import arm_const as ar
import build_lut_cp_publication as build
import build_lut_handoff_ap as apbuild
import verify_lut_reader_placement as readers
from verify_lut_handoff_ap import Core
from verify_upload_guards import Guarded
from verify_shared_buffer_interleaving import OBJ,TARGET

B=build.base
v=readers.v
CODE=0x90000
RX=v.RAM+0xd000
INPUT,OUTPUT=v.RAM+0xe000,v.RAM+0xe100
AP_INPUT=0x10007000


class Peer(readers.Owner):
    def __init__(self,cp,payload,parent,code,r,fault=None,finish_contention=False):
        self.rx_code=code;self.rx_recipe=r;self.packet_length=None
        self.publications=0;self.mapping_calls=[];self.fault=fault
        self.finish_contention=finish_contention
        super().__init__(cp,payload,parent)
        self.u.mem_map(CODE,4096);self.u.mem_write(CODE,code)
        self.u.mem_protect(CODE,4096,UC_PROT_READ|UC_PROT_EXEC)
        self.u.mem_write(RX,bytes(116));v.put(self.u,OBJ,0xffffffff)
        v.put(self.u,v.G+0xc0,17)

    def memory(self,u,access,address,size,value,unused):
        if access==UC_MEM_READ and self.packet_length is not None and INPUT<=address<INPUT+128:
            assert address+size<=INPUT+self.packet_length,('packet overread',address-INPUT,size,self.packet_length)
        super().memory(u,access,address,size,value,unused)

    def code(self,u,pc,size,unused):
        if CODE<=pc<CODE+len(self.rx_code):return
        if pc==0x35c54c:
            self.publications+=1
            assert v.word(u,B.component.GATE)==0xc0000000
            assert v.word(u,self.placement['state']+24)==3
        if pc==0x35c68a:
            if self.finish_contention:v.put(u,self.placement['state'],1)
            if self.fault=='length':v.put(u,v.G+0x78,47999)
            if self.fault=='art_address':v.put(u,v.G+0x70,v.word(u,v.G+0x70)^4)
            if self.fault=='generation':v.put(u,v.G+0xc0,17)
        if 0x35c54c<=pc<0x35c694:return
        a=[u.reg_read(v.reg(i)) for i in range(4)]
        if pc==0xb44b96:
            assert a[:2] in ([OBJ,5],[OBJ,0xb5])
            self.mapping_calls.append('release');v.put(u,OBJ,0xffffffff);self.ret();return
        if pc==0xb44a2c:
            assert a[:3]==[OBJ,1,5]
            self.mapping_calls.append('acquire')
            if self.fault!='mapping':u.mem_write(OBJ+0x10,struct.pack('<Q',TARGET))
            self.ret(int(self.fault=='mapping'));return
        if pc==0x61ed00:
            u.mem_write(a[0],bytes(a[1]));self.ret();return
        super().code(u,pc,size,unused)

    def receive(self,packet):
        self.u.mem_write(INPUT,packet or b'\0');self.u.mem_write(OUTPUT,b'\xa5'*40)
        self.packet_length=len(packet)
        u=self.u
        for reg,value in self.saved.items():u.reg_write(reg,value)
        for i,value in enumerate((self.placement['state'],RX,INPUT,len(packet))):u.reg_write(v.reg(i),value)
        v.put(u,v.SP,OUTPUT);u.reg_write(ar.UC_ARM_REG_SP,v.SP);u.reg_write(ar.UC_ARM_REG_LR,v.STOP|1)
        u.emu_start((CODE+self.rx_recipe['symbols']['lh_cp_receive_publication'])|1,v.STOP,count=100000)
        assert u.reg_read(ar.UC_ARM_REG_PC)==v.STOP
        assert u.reg_read(ar.UC_ARM_REG_SP)==v.SP
        assert all(u.reg_read(reg)==value for reg,value in self.saved.items())
        assert u.mem_read(OUTPUT+32,8)==b'\xa5'*8
        self.packet_length=None
        return u.reg_read(v.reg(0)),bytes(u.mem_read(OUTPUT,32))


def request(op=1,id=1,generation=17):return readers.lease.request(id=id,op=op,generation=generation)


def assert_reply(peer,p,status):
    result,out=peer.receive(p)
    assert result==2 and out[15]==status,(result,out.hex(),status)
    return out


def main():
    cp,payload,pr,code,r=build.make()
    ap,aprecipe=apbuild.make()
    manifest=json.loads((B.HERE/'dev-menu-03/manifest.json').read_text())
    messages={}
    for art in (False,True):
        upload=Guarded(ap,manifest,b'\x52'*(48124 if art else 48000),special=art)
        messages[art]=upload.execute(system=2)
        assert len(messages[art])==96
    def peer(**kw):
        p=Peer(cp,payload,pr,code,r,**kw);p.open();return p
    paired=[]
    for art in (False,True):
        host=Core(ap,aprecipe);host.opened();n=peer()
        assert n.produce(art)==([1,3,2] if art else [1,2])
        def transmit(descriptor=b''):
            assert host.call('lh_ap_request',AP_INPUT)==32
            packet=bytes(host.u.mem_read(AP_INPUT,32))+descriptor
            result,out=n.receive(packet)
            if result==2:host.receive(out)
            return result,out
        assert transmit()[1][15]==1 and host.call('lh_ap_write',1)==0
        assert n.work(cp,payload).results==[0]*len(n.queued)
        assert transmit()[1][15]==0 and host.call('lh_ap_write',1)==1
        # Execute the native uploader after permission, in its explicit upload
        # fixture. AP core/owner integration and message assembly/delivery are
        # still test wiring. Native CP publication is owned by the new receiver.
        upload=Guarded(ap,manifest,b'\x52'*(48124 if art else 48000),special=art)
        descriptor=upload.execute(system=2)
        assert descriptor==messages[art]
        assert host.call('lh_ap_written',1,1)==1
        assert transmit(descriptor)[1][15]==0
        assert host.phase()==1 and n.publications==1 and v.word(n.u,v.G+0xc0)==18
        assert n.receive(request(op=2)+messages[art])[1][15]==0 and n.publications==1
        token=n.core('lh_cp_reader_begin');assert token
        assert n.core('lh_cp_reader_end',token)==1
        paired.append({'art':art,'native_queued_readers_drain_before_permission':True,
                       'ap_idle_after_compiled_receiver_publish_reply':True,'duplicate_publish_runs_native_once':True})
    malformed=[]
    complete=request(op=2)+messages[True]
    candidates=[complete[:length] for length in range(128)]+[complete+b'\0']
    for offset,value in [(1,1),(12,2),(13,1),(15,1),(28,1),(16,1),(4,0),
                         (32,0),(52,0),(60,1),(56,0)]:
        p=bytearray(complete);p[offset]=value;candidates.append(bytes(p))
    for offset,value in [(40,0),(44,0xffffffff),(48,0xffffffff),(60,125)]:
        p=bytearray(complete);struct.pack_into('<I',p,offset,value);candidates.append(bytes(p))
    for index,p in enumerate(candidates):
        n=peer();assert_reply(n,request(),0)
        before=bytes(n.u.mem_read(n.placement['state'],148))
        kind,_=n.receive(p)
        assert kind in (0,1,2) and n.publications==0,(index,len(p),kind,n.publications)
        assert bytes(n.u.mem_read(n.placement['state'],148))==before
        malformed.append({'index':index,'length':len(p),'result':kind,'no_native_publication':True})
    legacy=peer();kind,_=legacy.receive(messages[False]);assert kind==1 and legacy.publications==0
    ordinary=[]
    for label,offset,value in [('other_command',2,0x57),('reply_type',0,1)]:
        n=peer();p=bytearray(request());p[offset]=value
        before=bytes(n.u.mem_read(n.placement['state'],148))
        assert n.receive(bytes(p))[0]==0 and not n.publications
        assert n.u.mem_read(n.placement['state'],148)==before
        ordinary.append(label)
    no_permission=[]
    for art in (False,True):
        n=peer();assert_reply(n,request(op=2)+messages[art],2)
        assert not n.publications and n.bits()==0
        token=n.core('lh_cp_reader_begin');assert token
        assert_reply(n,request(),1)
        assert_reply(n,request(op=2)+messages[art],2)
        assert n.publications==0 and n.bits()!=0
        assert n.core('lh_cp_reader_end',token)==1
        no_permission.append({'art':art,'publish_without_grant_or_while_waiting_denied':True})
    changed=[]
    for art in (False,True):
        n=peer();assert_reply(n,request(),0)
        assert_reply(n,request(op=2)+messages[art],0)
        p=bytearray(request(op=2)+messages[art]);p[-1]^=1
        assert n.receive(bytes(p))[0]==1 and n.publications==1
        assert_reply(n,request(op=2)+messages[art],0)
        changed.append({'art':art,'changed_duplicate_consumed_without_republish':True})
    faults=[]
    for fault,art in [('mapping',False),('mapping',True),('length',False),('art_address',True),('generation',False)]:
        n=peer(fault=fault);assert_reply(n,request(),0)
        out=assert_reply(n,request(op=2)+messages[art],2)
        generation=v.word(n.u,v.G+0xc0)
        assert v.word(n.u,n.placement['state']+28)==generation
        assert struct.unpack_from('<I',out,24)[0]==generation
        assert n.core('lh_cp_reader_begin')==0
        assert_reply(n,request(op=3),0)
        assert n.core('lh_cp_reader_begin')==0
        faults.append({'fault':fault,'art':art,'observed_generation':generation,'invalid_after_cancel':True})
    resume=[]
    for next_op in (2,3):
        n=peer(finish_contention=True);assert_reply(n,request(),0)
        envelope=request(op=2)+messages[True]
        assert n.receive(envelope)[0]==1
        assert n.publications==1 and v.word(n.u,RX+4)==1
        assert n.core('lh_cp_reader_begin')==0
        assert n.receive(envelope)[0]==1 and n.publications==1
        v.put(n.u,n.placement['state'],0)
        followup=envelope if next_op==2 else request(op=3)
        out=assert_reply(n,followup,0)
        assert out[14]==next_op and n.publications==1 and v.word(n.u,RX+4)==0
        token=n.core('lh_cp_reader_begin');assert token
        resume.append({'followup_operation':next_op,'native_once_despite_finish_contention':True,
                       'pending_completion_resumed':True,'reply_matches_current_request':True})
    locks=[]
    for which in ('receiver','core'):
        n=peer();v.put(n.u,RX if which=='receiver' else n.placement['state'],1)
        assert n.receive(request())[0]==1 and not n.publications
        v.put(n.u,RX if which=='receiver' else n.placement['state'],0)
        assert_reply(n,request(),0)
        locks.append(which)
    cancellations=[]
    for art in (False,True):
        n=peer();assert_reply(n,request(),0);assert_reply(n,request(op=3),0)
        assert_reply(n,request(op=2)+messages[art],2)
        assert n.publications==0 and n.core('lh_cp_reader_begin')==0
        assert_reply(n,request(id=2),0)
        assert_reply(n,request(id=2,op=2)+messages[art],0)
        assert n.publications==1 and n.core('lh_cp_reader_begin')
        cancellations.append({'art':art,'cancelled_id_never_published':True,'next_id_recovers':True})
    report={'status':'CP_PUBLICATION_RECEIVER_COMPONENT_VERIFIED_NOT_FLASHABLE','camera_io':False,
            'component_sha256':B.b.sha((build.OUT/'component.json').read_bytes()),
            'parent_cp_sha256':pr['in_memory_cp_sha256'],'paired_flows':paired,'malformed':malformed,
            'legacy_native_packet_rejected':True,'changed_duplicates':changed,'publication_faults':faults,
            'ordinary_passthrough':ordinary,'publish_without_permission':no_permission,
            'finish_contention':resume,'lock_contention':locks,'cancel_recovery':cancellations,
            'source_sha256':{name:B.b.sha((B.HERE/name).read_bytes()) for name in
                             ('verify_lut_cp_publication.py','verify_lut_reader_placement.py','verify_lut_handoff_ap.py',
                              'verify_lut_handoff_cp.py','verify_upload_guards.py','verify_lut_upload.py',
                              'verify_shared_buffer_interleaving.py','verify_lut_dma_worker.py','verify_queue_completion.py',
                              'verify_queue_allocation_guard.py','verify_lut_ownership.py','verify_resource_release.py')},
            'limitations':['Receiver code/state placement at emulator addresses is explicit; no real IPC dispatch or reply-send adapter is installed.',
                           'AP envelope assembly and delivery are fixtures; the native uploader and AP core still need a production owner.',
                           'Existing 32-byte PUBLISH must be extended with 96 descriptor bytes; legacy native 4155 is rejected by this component.',
                           'Input buffer immutability/length and output capacity are receiver-adapter contracts, not yet proven for the native ingress.',
                           'OS, mapping, physical transfer/DMA and scheduling are fixtures. External source ownership, WBI and installation remain incomplete.']}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'paired':len(paired),'malformed':len(malformed),
                      'faults':len(faults),'finish_contention':len(resume),'changed_duplicates':len(changed),
                      'cancel_recovery':len(cancellations)}))


if __name__=='__main__':main()
