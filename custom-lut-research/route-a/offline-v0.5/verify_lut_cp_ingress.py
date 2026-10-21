"""Execute native allocator/queue/worker plus the new IPC dispatch bridge.

Heap allocation/free, registry/locks and cross-processor delivery are explicit
fixtures. Message metadata, local queue, worker, send-copy and publication run
as native instructions. Code/state placement is still emulator-only.
"""
import json
import struct
from pathlib import Path
from unicorn import UC_MEM_READ, UC_PROT_READ, UC_PROT_EXEC
from unicorn import arm_const as ar
import build_lut_cp_ingress as build
import verify_lut_cp_publication as publication

v = publication.v
b = build.b
AREA, Q1, Q2, SLOT, NETWORK, TRANSPORT = 0x3400000,0x3400000,0x3400040,0x3400100,0x3400200,0xb0000
CP_PORT, AP_PORT = 0x90030001,0x80020002
RANGES = [(0x565204,0x5652d0),(0x565644,0x5657e8),(0x564b38,0x564ca2),
          (0x5653a8,0x5655dc),(0xbebc92,0xbec01c),(0x565300,0x565398),
          (0xbec070,0xbec0f8),(0xbec024,0xbec030),(0xbec28e,0xbec2a0),
          (0x4b3a7c,0x4b3b40),(0x4b3c48,0x4b3cca),(0x35cf70,0x35d090),
          (0x4b3b74,0x4b3bd4),(0x512b24,0x512b98),(0x563aa4,0x563adc)]


class IPC(publication.Peer):
    def __init__(self, bundle, send_fault=None, **kw):
        cp,payload,pr,code,r,adapter,self.adapter = bundle
        self.send_fault=send_fault;self.ipc_allocations={};self.frees=[];self.sent=[]
        self.ipc_heap=AREA+0x1000;self.queue_running=False;self.locked=False
        self.current=None;self.consumed=False;self.original_dispatches=0;self.replies_attempted=0
        self.message_bound=None;self.bridge_saved=None;self.bridge_returns=0
        super().__init__(cp,payload,pr,code,r,**kw)
        self.u.mem_map(AREA,0x10000)
        self.u.mem_map(build.INGRESS_CODE,4096);self.u.mem_write(build.INGRESS_CODE,adapter)
        self.u.mem_protect(build.INGRESS_CODE,4096,UC_PROT_READ|UC_PROT_EXEC)
        self.u.mem_map(TRANSPORT,4096);self.u.mem_write(TRANSPORT,b'\x70\x47')
        v.put(self.u,0x120f7c0+12,Q1);v.put(self.u,0x120f7c0+16,Q2)
        v.put(self.u,0x1a7e968,NETWORK);v.put(self.u,NETWORK,TRANSPORT|1)
        self.open()

    def code(self,u,pc,size,unused):
        args=[u.reg_read(v.reg(i)) for i in range(4)]
        if build.INGRESS_CODE<=pc<build.INGRESS_CODE+self.adapter['code_bytes']:return
        if pc==0x4b3a9e and self.consumed:
            assert not self.locked
            u.emu_stop();return
        if pc==0x35cf70:self.original_dispatches+=1
        if pc==0x4b3c48:self.replies_attempted+=1
        if pc==build.HOOK:
            self.bridge_saved=([u.reg_read(v.reg(i)) for i in range(4,12)],u.reg_read(ar.UC_ARM_REG_SP))
        if pc==0x4b3b30 and self.bridge_saved is not None:
            assert self.bridge_saved==([u.reg_read(v.reg(i)) for i in range(4,12)],u.reg_read(ar.UC_ARM_REG_SP))
            self.bridge_saved=None;self.bridge_returns+=1
        if pc==0xbeb99a:
            assert args[0] in (1,2),args
            self.ret(Q1 if args[0]==1 else Q2);return
        if pc==0x566378:
            assert args[0]==0x1b20c00 and 64<=args[1]<=4352
            if self.queue_running and self.send_fault=='allocation':self.ret(0);return
            ptr=self.ipc_heap;self.ipc_heap+=0x1200
            assert self.ipc_heap<AREA+0x10000
            self.ipc_allocations[ptr]=args[1];u.mem_write(ptr,b'\xa5'*args[1])
            v.put(u,args[3],0);self.ret(ptr);return
        if pc==0x566528:
            assert args[0]==0x1b20c00 and self.ipc_allocations.pop(args[1])==args[2],args
            self.frees.append(args[1]);u.mem_write(args[1],b'\xdd'*args[2]);self.ret();return
        if pc==TRANSPORT:
            assert args[0]==AP_PORT
            pointer=args[1];n=v.word(u,pointer-8)
            assert n==32 and v.word(u,pointer-12)==CP_PORT
            assert not (v.SP-1024<=pointer<v.SP)
            snapshot=bytes(u.mem_read(pointer,n))
            if self.send_fault=='enqueue':self.ret(-1)
            else:self.sent.append((pointer,snapshot));self.ret()
            return
        if pc==0x565300 and args[:2]==[CP_PORT,self.current]:
            assert self.queue_running and not self.locked and not self.consumed
            self.consumed=True;self.message_bound=None
        if pc in (0xbeb7dc,0xbeb838,0x6031b4):self.ret();return
        if pc==0x5e23b4:
            assert args[0]==0x26 and not self.locked;self.locked=True;self.ret();return
        if pc==0x5e1f58:
            assert args[0]==0x26 and self.locked;self.locked=False;self.ret();return
        if pc==0x5f267c:self.ret(0);return  # explicit thread-context fixture
        if pc==0x5e9834:
            assert args[:2]==[0x4a,1]  # native low-memory notification boundary
            self.ret();return
        if pc in (0xb4457a,0x605c3c):self.ret();return
        if pc==0x61e60c:
            dst,src,n=args[:3];assert n<=4096
            u.mem_write(dst,bytes(u.mem_read(src,n)));self.ret(dst);return
        if any(lo<=pc<hi for lo,hi in RANGES):return
        super().code(u,pc,size,unused)

    def memory(self,u,access,address,size,value,unused):
        if access==UC_MEM_READ and self.message_bound:
            start,n=self.message_bound
            if start<=address<start+4096:
                assert address+size<=start+n,('message overread',address-start,size,n)
        super().memory(u,access,address,size,value,unused)

    def deliver(self,packet,metadata_length=None,native_copy=False):
        self.queue_running=False;self.consumed=False
        if native_copy:
            self.u.mem_write(AREA+0xd000,packet)
            self.call(0x4b3b74,AP_PORT,AREA+0xd000,len(packet))
            header=v.word(self.u,Q1+8);assert header
            pointer=header+0x18
            assert bytes(self.u.mem_read(pointer,len(packet)))==packet
            self.u.mem_write(AREA+0xd000,b'\xee'*len(packet))
        else:
            assert self.call(0x565204,CP_PORT,SLOT,len(packet),0)==0
            pointer=v.word(self.u,SLOT)
            self.u.mem_write(pointer,packet or bytes(4))
            self.call(0xbec024,pointer,AP_PORT)
            # Explicit transport boundary: enqueue the received allocation.
            assert self.call(0x564b38,CP_PORT,pointer)==0
        n=self.call(0xbec28e,pointer)
        assert n==(len(packet) or 4),n
        assert self.call(0xbec28e,0)==0xfffffc00
        if metadata_length is not None:v.put(self.u,pointer-8,metadata_length)
        self.current=pointer;self.message_bound=(pointer,len(packet) or 4)
        before_frees=len(self.frees);before_sent=len(self.sent)
        self.queue_running=True
        self.u.reg_write(ar.UC_ARM_REG_SP,v.SP)
        self.u.reg_write(ar.UC_ARM_REG_LR,v.STOP|1)
        self.u.emu_start(0x4b3a7d,v.STOP,count=200000)
        assert self.u.reg_read(ar.UC_ARM_REG_PC)==0x4b3a9e
        assert self.u.reg_read(ar.UC_ARM_REG_SP)==v.SP-40
        assert self.consumed and not self.locked
        assert len(self.frees)>=before_frees+1
        assert pointer-0x18-0x28 not in self.ipc_allocations
        assert v.word(self.u,Q1+8)==0
        # Stack source and request were both reclaimed; queued reply owns copy.
        self.u.mem_write(v.SP-1024,b'\xcc'*1024)
        for p,snapshot in self.sent[before_sent:]:assert bytes(self.u.mem_read(p,32))==snapshot
        self.queue_running=False
        return [x[1] for x in self.sent[before_sent:]]


def main():
    bundle=build.make()
    manifest=json.loads((b.HERE/'dev-menu-03/manifest.json').read_text())
    ap=(b.HERE/'dev-menu-03/candidate/appFw.so').read_bytes()
    descriptors={art:publication.Guarded(ap,manifest,b'\x52'*(48124 if art else 48000),special=art).execute(system=2)
                 for art in (False,True)}
    flows=[]
    for art in (False,True):
        n=IPC(bundle)
        assert n.deliver(publication.request())[0][15]==0
        packet=publication.request(op=2)+descriptors[art]
        assert n.deliver(packet)[0][15]==0 and n.publications==1
        assert n.deliver(packet)[0][15]==0 and n.publications==1
        assert n.original_dispatches==0
        flows.append({'art':art,'native_publications':n.publications,'replies':len(n.sent),
                      'request_frees':len(n.frees),'duplicate_idempotent':True})
    n=IPC(bundle)
    assert n.deliver(publication.request(),native_copy=True)[0][15]==0
    assert n.deliver(publication.request(op=2)+descriptors[True],native_copy=True)[0][15]==0
    assert n.publications==1
    faults=[]
    for fault in ('allocation','enqueue'):
        n=IPC(bundle);assert n.deliver(publication.request())[0][15]==0
        n.send_fault=fault;packet=publication.request(op=2)+descriptors[False]
        frees_before=len(n.frees);allocated_before=len(n.ipc_allocations)
        assert n.deliver(packet)==[] and n.publications==1
        assert len(n.frees)-frees_before==(2 if fault=='enqueue' else 1)
        assert len(n.ipc_allocations)==allocated_before
        n.send_fault=None
        assert n.deliver(packet)[0][15]==0 and n.publications==1
        faults.append({'fault':fault,'retry_ack_without_republish':True,'no_request_leak':True})
    malformed=[]
    packet=publication.request(op=2)+descriptors[True]
    for length in (1,2,3,4,8,15,16,31,33,95,96,127,129):
        n=IPC(bundle);p=(packet+b'\0')[:length]
        assert n.deliver(p)==[] and not n.publications and not n.original_dispatches
        malformed.append(length)
    n=IPC(bundle);assert n.deliver(publication.request(),metadata_length=4097)==[]
    assert not n.publications and not n.original_dispatches
    n=IPC(bundle);assert n.deliver(descriptors[False])==[]
    assert not n.publications and not n.original_dispatches
    n=IPC(bundle);unknown=bytes.fromhex('0500ffff00000000')
    assert n.deliver(unknown)==[] and n.original_dispatches==1
    n=IPC(bundle);token=n.core('lh_cp_reader_begin');assert token
    assert n.deliver(publication.request())[0][15]==1
    assert n.deliver(publication.request(op=2)+descriptors[False])[0][15]==2
    assert not n.publications
    assert n.core('lh_cp_reader_end',token)==1
    assert n.deliver(publication.request())[0][15]==0
    assert n.deliver(publication.request(op=2)+descriptors[False])[0][15]==0
    assert n.publications==1 and n.bits()==0
    n=IPC(bundle,finish_contention=True)
    assert n.deliver(publication.request())[0][15]==0
    assert n.deliver(publication.request(op=2)+descriptors[False])==[]
    assert n.publications==1 and v.word(n.u,build.PUBLICATION_STATE+4)==1
    v.put(n.u,n.placement['state'],0)
    assert n.deliver(publication.request(op=3))[0][15]==0
    assert n.publications==1 and v.word(n.u,build.PUBLICATION_STATE+4)==0
    n=IPC(bundle,fault='mapping');assert n.deliver(publication.request())[0][15]==0
    assert n.deliver(publication.request(op=2)+descriptors[False])[0][15]!=0
    assert v.word(n.u,publication.B.component.GATE)&0x40000000
    assert n.deliver(publication.request(op=3))[0][15]==0
    assert v.word(n.u,publication.B.component.GATE)&0x40000000
    report={'status':'NATIVE_CP_QUEUE_DISPATCH_AND_REPLY_COPY_VERIFIED','camera_io':False,
            'component_sha256':b.sha((build.OUT/'component.json').read_bytes()),
            'flows':flows,'reply_failures':faults,'malformed_lengths':malformed,
            'oversize_metadata_rejected':True,'unrelated_command_native_dispatch':True,
            'legacy_native_upload_rejected':True,'reader_busy_until_end_then_publish':True,
            'pending_finish_resumed_by_cancel':True,'mapping_failure_remains_invalid':True,
            'bridge_preserves_callee_saved_and_stack':True,
            'native_copy_helper_preserves_requested_length_and_owns_copy':True,
            'source_sha256':{name:b.sha((b.HERE/name).read_bytes()) for name in (
                Path(__file__).name,'verify_lut_cp_publication.py','verify_resource_release.py',
                'build_lut_cp_ingress.py','lut_cp_ingress.c')},
            'limitations':['Code/state are at explicit emulator addresses; boot placement remains pending.',
                           'Physical AP-to-CP transfer and receive allocation provenance remain external boundaries.',
                           'Heap, registry, lock effects and remote delivery are fixtures; native queue/free metadata instructions execute.',
                           'Low-memory event delivery is acknowledged by an OS fixture; its asynchronous handler is not executed.',
                           'AP production upload owner, session initialization, deadlines and installer remain incomplete.']}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('status','flows','reply_failures','malformed_lengths')}))


if __name__=='__main__':main()
