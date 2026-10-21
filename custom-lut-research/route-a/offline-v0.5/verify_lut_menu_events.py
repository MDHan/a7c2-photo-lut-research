"""Native cancel virtual dispatch, deletion gates and timeout recovery, offline."""
import json,struct
from verify_lut_handoff_ap import Core
from pathlib import Path
from unicorn import arm64_const as a
import verify_lut_events_integration as runtime
b=runtime.b;RAM=runtime.RAM;X=runtime.X;TRAMP=runtime.TRAMP

class Menu(runtime.Owner):
    def __init__(self,*args,**kwargs):
        self.unlinked=[];self.reset_calls=[];self.cancel_dispatches=0;self.unlink_fault=False
        super().__init__(*args,**kwargs)
    def run(self,entry,args=(),allowed=()):
        if entry not in (0x3021338,0x302138c,0x34c4a88):return super().run(entry,args,allowed)
        self.allowed=list(allowed)+[(0x302040c,0x3020430)]
        for i,value in enumerate(args):self.u.reg_write(X(i),value)
        saved={X(i):0x22220000+i for i in range(19,30)}
        for reg,value in saved.items():self.u.reg_write(reg,value)
        self.u.reg_write(a.UC_ARM64_REG_SP,runtime.STACK+0xff00);self.u.reg_write(a.UC_ARM64_REG_LR,runtime.STOP)
        self.u.emu_start(entry,runtime.STOP,count=4000000)
        assert self.u.reg_read(a.UC_ARM64_REG_PC)==runtime.STOP
        assert self.u.reg_read(a.UC_ARM64_REG_SP)==runtime.STACK+0xff00
        assert all(self.u.reg_read(reg)==value for reg,value in saved.items())
        return self.u.reg_read(X(0))
    def inject(self,u,pc,kind,first,cookie=None):
        if kind!='cancel':return super().inject(u,pc,kind,first,cookie)
        assert self.schedule is None
        self.schedule=(u.context_save(),kind,cookie)
        node=RAM+0x1b000;obj=node+0x100;task=self.qword(self.state+216)
        self.write(node+8,struct.pack('<Q',obj));self.write(obj+0x10,struct.pack('<Q',task))
        u.reg_write(X(19),node);u.reg_write(a.UC_ARM64_REG_SP,runtime.STACK+0x7000)
        u.reg_write(a.UC_ARM64_REG_PC,0x3209b18)
    def code(self,u,pc,size,unused):
        if self.schedule and self.schedule[1]=='cancel' and pc==0x3209b2c:
            self.cancel_dispatches+=1;u.reg_write(a.UC_ARM64_REG_PC,TRAMP);return
        if pc==0x165ded0:
            args=[u.reg_read(X(i)) for i in range(5)];fmt=self.string(args[2]);root=self.string(args[3])
            assert fmt in ('%s/LUT%03d.LUT','%s/LUT%03d.cube','%s/LUT%03d.CUBE'),fmt
            assert root=='/usr/data/lut' and args[1]==26
            name=fmt%(root,args[4]);self.write(args[0],name.encode()+b'\0');self.ret(len(name));return
        if pc==0x165ea30:
            self.unlinked.append(self.string(u.reg_read(X(0))));self.ret(1 if self.unlink_fault else 0);return
        if pc==self.r['symbols']['lh_reset_original']:
            self.reset_calls.append(self.qword(self.state+216))
            # Native model/notification services are not reimplemented here.
            # Execute its real selective helper under the confirmed flag.
            u.reg_write(X(1),self.word(u.reg_read(X(0))+0x1c))
            u.reg_write(a.UC_ARM64_REG_PC,0x34c4878);return
        if pc in (0x34cfa48,0x34cfa88,0x34c6418):
            self.put(u.reg_read(X(1)),0);self.ret();return
        if 0x3209b18<=pc<=0x3209b28 or 0x34c4878<=pc<0x34c499c:return
        super().code(u,pc,size,unused)
    def delete(self,slot=0,cube=False):
        return self.run(0x302138c if cube else 0x3021338,(slot,),runtime.RANGES+[(0x3021338,0x30213e0)])
    def reset(self,selected=3,deleted=3):
        task=RAM+0x1c000;self.write(task,bytes(0x48));self.put(task+0x14,2)
        self.put(task+0x18,selected);self.put(task+0x1c,deleted)
        self.run(0x34c4a88,(task,),runtime.RANGES+[(0x34c4a88,0x34c4c24)])
        return self.result()

def main():
    raw,r=runtime.build.make();bundle=runtime.cp_bundle();cases=[];rebased=[]
    for bias in (0,0x10000000,0x7100000000):
        h=Core(raw,r['core_layout'],bias);h.write(h.state,bytes(r['state_bytes']));h.opened()
        task=RAM+0x4000;node=RAM+0x5000;obj=RAM+0x5100;slot=bias+0x5b3db40
        h.write(h.state+216,struct.pack('<Q',task));h.write(node+8,struct.pack('<Q',obj))
        h.write(obj+0x10,struct.pack('<Q',task));h.write(task,struct.pack('<Q',bias+0x5b3db20))
        assert h.qword(slot)==r['symbols']['lh_menu_cancel']
        # Materialize the inspected RELATIVE relocation, as the loader does.
        h.write(slot,struct.pack('<Q',bias+r['symbols']['lh_menu_cancel']))
        h.allowed=[(bias+0x3209b18,bias+0x3209b2c),(h.base,h.base+h.recipe['payload_size'])]
        h.ensure(bias+0x3209b18,24)
        h.u.reg_write(X(19),node);h.u.reg_write(a.UC_ARM64_REG_SP,runtime.STACK+0xf000)
        h.u.emu_start(bias+0x3209b18,bias+0x3209b2c,count=1000)
        assert h.phase()==7 and h.word(h.state+240)==1
        assert h.u.reg_read(a.UC_ARM64_REG_SP)==runtime.STACK+0xf000
        rebased.append({'bias':hex(bias),'native_virtual_dispatch_after_relative_relocation':True})
    def host(**kw):return Menu(raw,r,runtime.SessionIPC(bundle),**kw)
    n=host(cancel_at=40,delay=100)
    assert n.execute_task()==-125 and n.cancel_dispatches==1 and n.phase()==5 and n.transfer_state()==1
    n.cancel_at=None;n.delay=20
    assert n.execute_task()==0
    cases.append({'native_manager_cancel_virtual_dispatch':True,'late_completion_then_retry':True})
    n=host(cancel_at=10,fault='no_replies')
    assert n.execute_task()==-125 and n.cancel_dispatches==1 and not n.copy_times and not n.dma_submits
    assert n.clock<100 and not n.unlinked
    n.cancel_at=None;n.owner_fault=None
    assert n.execute_task()==0
    cases.append({'native_cancel_during_hello_before_transaction_id':True,'no_file_copy_and_next_task_recovers':True})
    n=host(cancel_at=40,delay=100)
    assert n.execute_task()==-125
    n.cancel_at=None
    assert n.delete()==0 and n.unlinked
    cases.append({'cancelled_task_flag_does_not_poison_next_delete':True})
    n=host();n.peer.open()
    # SessionIPC.open deliberately does nothing: use a real HELLO so the busy
    # reader belongs to the same entropy-backed session as the AP task.
    n.cancel_at=40
    # Existing upload first establishes the session, then a held reader makes
    # the next upload wait for permission while native cancel is dispatched.
    n.cancel_at=None;assert n.execute_task()==0
    token=n.peer.core('lh_cp_reader_begin');assert token
    n.cancel_at=n.clock+20;n.cancelled=False
    assert n.execute_task()==-125 and n.cancel_dispatches==1 and n.peer.bits()
    assert n.peer.core('lh_cp_reader_end',token)==1
    n.cancel_at=None;assert n.execute_task()==0
    cases.append({'native_cancel_while_waiting_for_readers':True,'reader_not_forcibly_released':True})
    n=host();assert n.execute_task()==0;before=n.peer.publications
    assert n.delete()==0 and len(n.unlinked)==1 and n.unlinked[0].endswith('/LUT001.LUT')
    assert n.peer.publications==before+1 and n.word(n.state+232)==0
    assert bytes(n.peer.u.mem_read(runtime.ipc.v.G+0x68,24))==bytes(24)
    assert n.delete(cube=True)==0 and len(n.unlinked)==2
    cases.append({'native_lut_and_cube_path_delete':True,'clear_ack_before_unlink':True})
    n=host();assert n.execute_task()==0;before=n.peer.publications
    assert n.delete(1)==0 and n.peer.publications==before and n.word(n.state+232)==3
    cases.append({'unrelated_slot_delete_preserves_current_lut':True})
    n=host();assert n.execute_task()==0;n.unlink_fault=True
    assert n.delete()==1 and n.word(n.state+232)==0
    n.unlink_fault=False
    assert n.delete()==0 and len(n.unlinked)==2
    cases.append({'unlink_failure_return_preserved_after_confirmed_clear':True,'retry_does_not_restore_stale_lut':True})
    n=host();assert n.execute_task()==0
    token=n.peer.core('lh_cp_reader_begin');assert token
    assert n.delete()==3 and not n.unlinked and n.peer.bits()
    assert n.peer.core('lh_cp_reader_end',token)==1
    assert n.delete()==0 and len(n.unlinked)==1
    cases.append({'delete_waits_for_reader_and_times_out_without_unlink':True,'release_then_retry':True})
    n=host(delay=None);assert n.execute_task()==-110
    assert n.delete()==3 and not n.unlinked and n.phase()==5 and n.transfer_state()==1
    cases.append({'missing_completion_blocks_delete_without_releasing_buffer':True})
    n=host(delay=6500);assert n.execute_task()==-110
    assert n.delete()==0 and len(n.unlinked)==1 and n.phase()==1
    cases.append({'late_completion_drained_before_file_delete':True})
    n=host();assert n.execute_task()==0;n.owner_fault='no_commit'
    assert n.delete()==0 and len(n.unlinked)==1
    cases.append({'clear_ack_loss_resolved_by_committed_cancel_before_delete':True})
    n=host();assert n.execute_task()==0;n.owner_fault='no_replies'
    assert n.delete()==3 and not n.unlinked
    cases.append({'unconfirmed_clear_never_deletes_file':True})
    n=host();assert n.execute_task()==0
    assert n.reset()==0 and len(n.reset_calls)==1
    cases.append({'native_reset_event_and_selective_helper':True,'legacy_clear_suppressed_after_protocol_ack':True})
    n=host();assert n.execute_task()==0;before=n.peer.publications
    assert n.reset(selected=3,deleted=4)==0 and len(n.reset_calls)==1 and n.peer.publications==before
    cases.append({'unrelated_reset_keeps_current_descriptor':True})
    report={'status':'NATIVE_CANCEL_DELETE_RESET_OFFLINE_VERIFIED_NOT_FLASHABLE','camera_io':False,
        'ap_sha256':b.sha(raw),'cp_sha256':b.sha(bundle[0]),
        'ap_recipe_sha256':b.sha((runtime.build.OUT/'recipe.json').read_bytes()),
        'cp_recipe_sha256':b.sha((runtime.cpbuild.OUT/'recipe.json').read_bytes()),'cases':cases,'rebased_cancel':rebased,
        'source_sha256':{Path(__file__).name:b.sha(Path(__file__).read_bytes()),'verify_lut_events_integration.py':b.sha((b.HERE/'verify_lut_events_integration.py').read_bytes())},
        'limitations':['Native manager cancel virtual dispatch is executed; the complete UI key/popup event producer is not locally proven.',
        'Reset task model bookkeeping is a fixture; its real selective helper and clear gate execute.',
        'Filesystem unlink, OSAL, kernel clock and physical transfer are services; no hardware abort is asserted.']}
    (runtime.build.OUT/'menu-events.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'cases':len(cases)}))
if __name__=='__main__':main()
