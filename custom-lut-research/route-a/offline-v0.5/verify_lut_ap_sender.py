"""Placed AP sender, native import ABI and paired CP receiver tests.

Allocation, OSAL delivery/free and memcpy are explicit fixtures. Paired tests
execute both compiled protocol peers and native CP queue/publication code.
"""
import json
import struct
from pathlib import Path
from verify_lut_handoff_ap import Core,packet,bridge_cases
from verify_menu import RAM,X
import build_lut_ap_sender as build
import build_lut_ingress_placement as cpbuild
import verify_lut_ingress_placement as cpcheck
import verify_lut_cp_ingress as ipc

b=build.b
MESSAGE,DESCRIPTOR=RAM+0x8000,RAM+0x7000


class Sender(Core):
    def __init__(self,raw,r,bias=0,fault=None):
        self.sender=r;self.fault=fault;self.events=[];self.sent=[];self.allocations=set()
        self.packet_length=None;self.source=None
        super().__init__(raw,r['combined_core_layout'],bias)

    def code(self,u,pc,size,unused):
        args=[u.reg_read(X(i)) for i in range(4)]
        pc-=self.bias
        if pc==build.SERVICES['lh_native_allocate']:
            assert args[0]==0x90030001 and args[2] in (32,128) and args[3]==1
            assert self.qword(args[1])==0 and not self.allocations
            self.events.append('allocate')
            if self.fault=='allocation':self.ret(-1&0xffffffff);return
            if self.fault=='null_success':self.ret();return
            self.packet_length=args[2];self.allocations.add(MESSAGE)
            self.write(MESSAGE,b'\xa5'*(self.packet_length+16))
            self.write(args[1],struct.pack('<Q',MESSAGE));self.ret();return
        if pc==build.SERVICES['lh_native_source']:
            assert args[:2]==[MESSAGE,0x80020002] and MESSAGE in self.allocations
            self.source=args[1];self.events.append('source_metadata');self.ret();return
        if pc==build.SERVICES['lh_native_copy']:
            dst,src,n=args[:3]
            if dst==MESSAGE:
                assert n==self.packet_length and self.source==0x80020002
                self.events.append('packet_copy')
            else:
                assert src==DESCRIPTOR and n==96
                self.events.append('descriptor_copy')
            self.write(dst,bytes(u.mem_read(src,n)));self.ret(dst);return
        if pc==build.SERVICES['lh_native_send']:
            assert args[:2]==[0x90030001,MESSAGE] and self.allocations=={MESSAGE}
            assert bytes(u.mem_read(MESSAGE+self.packet_length,16))==b'\xa5'*16
            self.events.append('send')
            if self.fault in ('send','free'):
                self.ret(-7&0xffffffff);return
            self.sent.append(bytes(u.mem_read(MESSAGE,self.packet_length)))
            self.allocations.remove(MESSAGE)  # explicit OSAL ownership transfer
            self.ret();return
        if pc==build.SERVICES['lh_native_free']:
            assert args[:2]==[0x90030001,MESSAGE] and self.allocations=={MESSAGE}
            self.events.append('free')
            if self.fault=='free':self.ret(-1&0xffffffff);return
            self.allocations.remove(MESSAGE);self.write(MESSAGE,b'\xdd'*self.packet_length)
            self.ret();return
        super().code(u,pc+self.bias,size,unused)

    def send(self,descriptor=None):
        if descriptor is not None:
            assert len(descriptor)==96;self.write(DESCRIPTOR,descriptor)
        before=self.snapshot();sent_before=len(self.sent)
        result=self.call('lh_ap_send_request',DESCRIPTOR if descriptor is not None else 0)
        assert self.snapshot()==before  # transport acceptance never grants/commits
        if len(self.sent)>sent_before:
            preserved=self.sent[-1]
            self.write(DESCRIPTOR,b'\xee'*96)
            assert bytes(self.u.mem_read(MESSAGE,len(preserved)))==preserved
        return result


def cp_bundle():
    cp,code,r=cpbuild.make()
    pub=(cpbuild.publication.OUT/'publication.bin').read_bytes()
    pubr=json.loads((cpbuild.publication.OUT/'component.json').read_text())
    off=(r['ingress_address']&~1)-cpbuild.CODE
    adapter=code[off:r['restore_code_start']-cpbuild.CODE]
    return (cp,code,r,pub,pubr,adapter,{'code_bytes':len(adapter)})


def main():
    raw,r=build.make();again,ar=build.make();assert raw==again and r==ar
    cases=[]
    for bias in (0,0x10000000,0x7100000000):
        for phase in ('acquire','publish','cancel'):
            for fault,expected in [(None,0),('allocation',1),('null_success',2),('send',1),('free',2)]:
                n=Sender(raw,r,bias,fault);n.opened()
                descriptor=bytes(range(96)) if phase=='publish' else None
                if phase=='publish':
                    n.receive(packet());assert n.call('lh_ap_write',1)==1
                    assert n.call('lh_ap_written',1,1)==1
                elif phase=='cancel':assert n.call('lh_ap_cancel',1)==1
                assert n.send(descriptor)==expected
                if fault=='free':assert n.allocations=={MESSAGE}
                else:assert not n.allocations
                if fault in ('allocation','null_success'):assert n.events==(['descriptor_copy'] if phase=='publish' else [])+['allocate']
                if fault=='send':assert n.events[-2:]==['send','free']
                if expected==0:
                    wire=n.sent[-1];assert len(wire)==(128 if phase=='publish' else 32)
                    assert wire[14]=={'acquire':1,'publish':2,'cancel':3}[phase]
                    if phase=='publish':assert wire[32:]==descriptor
                cases.append({'bias':hex(bias),'phase':phase,'fault':fault,'sender_result':expected,
                              'protocol_state_unchanged':True,'events':n.events})
    retry_cases=[]
    for phase in ('acquire','publish','cancel'):
        for fault in ('allocation','send'):
            n=Sender(raw,r,fault=fault);n.opened()
            descriptor=bytes(range(96)) if phase=='publish' else None
            if phase=='publish':
                n.receive(packet());assert n.call('lh_ap_write',1)==1
                assert n.call('lh_ap_written',1,1)==1
            elif phase=='cancel':assert n.call('lh_ap_cancel',1)==1
            state=n.snapshot();assert n.send(descriptor)==1 and n.snapshot()==state
            n.fault=None;assert n.send(descriptor)==0 and n.snapshot()==state and not n.allocations
            retry_cases.append({'phase':phase,'fault':fault,'same_transaction_retried':True})
    invalid=[]
    for state in ('unopened','idle','ready','write','publish_without_descriptor'):
        n=Sender(raw,r)
        if state!='unopened':
            assert n.call('lh_ap_open',0x1234,0x5678)==1
            if state!='idle':
                assert n.call('lh_ap_begin')==1;n.receive(packet())
                if state in ('write','publish_without_descriptor'):assert n.call('lh_ap_write',1)==1
                if state=='publish_without_descriptor':assert n.call('lh_ap_written',1,1)==1
        assert n.send()==2 and not n.events and not n.sent
        invalid.append(state)
    bundle=cp_bundle();manifest=json.loads((b.HERE/'dev-menu-03/manifest.json').read_text())
    paired=[]
    for art in (False,True):
        cp,code,cr,*_=bundle
        u,_=cpcheck.cold(cp,code,cr,art)
        peer=cpcheck.PlacedIPC(bundle,u)
        descriptor=ipc.publication.Guarded(raw,manifest,b'\x52'*(48124 if art else 48000),special=art).execute(system=2)
        n=Sender(raw,r);n.opened()
        assert n.send()==0 and n.phase()==2
        reply=peer.deliver(n.sent[-1],native_copy=True)
        assert len(reply)==1 and n.receive(reply[0])==1 and n.phase()==4
        assert n.call('lh_ap_write',1)==1
        # Actual file-to-shared-buffer owner is still pending; this boundary
        # explicitly declares completed transfer only for the protocol test.
        assert n.call('lh_ap_written',1,1)==1 and n.send(descriptor)==0
        replies=peer.deliver(n.sent[-1],native_copy=True)
        assert len(replies)==1 and peer.publications==1 and n.phase()==6
        # Drop first ack, retransmit a copied envelope; CP must not republish.
        assert n.send(descriptor)==0
        replies=peer.deliver(n.sent[-1],native_copy=True)
        assert n.receive(replies[0])==1 and n.phase()==1 and peer.publications==1
        paired.append({'art':art,'placed_ap_sender_and_cold_cp_ingress':True,'lost_commit_ack_retry_once':True})
    receiver_regression=bridge_cases(raw,r['combined_core_layout'])
    report={'status':'AP_PRIVATE_SENDER_NATIVE_ABI_AND_CP_PAIR_VERIFIED_NOT_FLASHABLE',
            'camera_io':False,'in_memory_ap_sha256':r['in_memory_ap_sha256'],
            'recipe_sha256':b.sha((build.OUT/'recipe.json').read_bytes()),'cases':cases,'rejected_phases':invalid,
            'paired':paired,'receiver_regression':receiver_regression,'retry_cases':retry_cases,'cp_recipe_sha256':b.sha((cpbuild.OUT/'recipe.json').read_bytes()),
            'source_sha256':{n:b.sha((b.HERE/n).read_bytes()) for n in
                (Path(__file__).name,'verify_lut_handoff_ap.py','verify_lut_ingress_placement.py','verify_lut_cp_ingress.py','verify_lut_cp_publication.py')},
            'limitations':['OSAL allocation, metadata, send, free and ordinary memcpy are service fixtures; physical delivery is untested.',
                           'Sender callsites in the actual upload task, exclusive owner, production sessions and deadlines remain pending.',
                           'Paired tests explicitly inject session initialization and completed shared-data transfer.',
                           'A failed free returns STOP with unresolved ownership; no automatic retry or forced release is permitted.',
                           'No full paired image or camera installation.']}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'cases':len(cases),'rejected_phases':len(invalid),'paired':len(paired),'same_transaction_retries':len(retry_cases),'receiver_regression':len(receiver_regression)}))


if __name__=='__main__':main()
