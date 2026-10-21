"""Execute actual native constructors/queue helper at OS allocation boundaries."""
import json
import struct
from pathlib import Path
import build_queue_allocation_guard as build
import verify_resource_release as release
import verify_lut_ownership as ownership

v=release.v
SOURCE=v.RAM+0x6000


class Queue(release.Native):
    def __init__(self,cp,allocation=0,enqueue=0,free=0):
        super().__init__(cp)
        self.allocation,self.enqueue_result,self.free_result=allocation,enqueue,free
        self.calls=[]
        self.u.mem_write(release.BUFFER,b'\xa5'*0x38)

    def code(self,u,pc,size,unused):
        args=[u.reg_read(v.reg(i)) for i in range(4)]
        if pc==0x565204:
            assert args[0]==0x2ae085a and args[2:]==[0x38,0]
            self.calls.append('allocate')
            if not self.allocation:v.put(u,args[1],release.BUFFER)
            self.ret(self.allocation);return
        if pc==0x564b38:
            assert args[:2]==[0x2ae085a,release.BUFFER]
            self.calls.append('enqueue')
            if not self.enqueue_result:self.queued.append(bytes(u.mem_read(release.BUFFER,0x38)))
            self.ret(self.enqueue_result);return
        if pc==0x565300:
            assert args[:2]==[0x2ae085a,release.BUFFER]
            self.calls.append('free')
            self.ret(self.free_result);return
        if pc==0x4e89f0:self.calls.append('callback')
        if 0xb799de<=pc<0xb79b84:return
        super().code(u,pc,size,unused)

    def construct(self,kind):
        if kind==1:
            self.u.mem_write(release.REQUEST,struct.pack('<2I',SOURCE,0xbb80))
            return self.call(0xb799de,0,release.REQUEST,0x4e89f1)
        if kind==3:
            self.u.mem_write(release.REQUEST,struct.pack('<2I',SOURCE,0x7c))
            return self.call(0xb79ab4,0,release.REQUEST,0x4e89f1)
        assert kind==2
        self.u.mem_write(release.REQUEST,struct.pack('<6I',1,2,3,4,5,6))
        return self.call(0xb79576,0,release.REQUEST,0x4e89f1)


def run(cp):
    results=[]
    for kind in (1,2,3):
        baseline=Queue(cp)
        assert baseline.construct(kind)==0
        assert baseline.calls==['allocate','enqueue'] and len(baseline.queued)==1
        msg=baseline.queued[0]
        assert len(msg)==0x38 and struct.unpack_from('<I',msg)[0]==kind
        assert struct.unpack_from('<I',msg,12)[0]==0x4e89f1
        if kind in (1,3):
            assert struct.unpack_from('<2I',msg,20)==(SOURCE,0x2ee0 if kind==1 else 0x1f)
            assert msg[4:8]==bytes(4) and msg[28:]==bytes(28)
        else:assert struct.unpack_from('<6I',msg,28)==(1,2,3,4,5,6)
        results.append({'kind':kind,'case':'success','result':0,'message':msg.hex()})
        for allocation in (1,5,-1,0x80000000):
            n=Queue(cp,allocation=allocation)
            assert n.construct(kind)==(-20&0xffffffff)
            assert n.calls==['allocate'] and not n.queued
            assert bytes(n.u.mem_read(release.BUFFER,0x38))==b'\xa5'*0x38
            assert not any(a<release.BUFFER+0x38 and a+s>release.BUFFER for _,a,s in n.accesses)
            results.append({'kind':kind,'case':'allocation_failure','allocation_status':allocation,
                            'result':-20,'no_message_access_or_free':True,'no_callback':True})
        for enqueue,free in ((1,0),(-1,0),(1,-1)):
            n=Queue(cp,enqueue=enqueue,free=free)
            assert n.construct(kind)==(-20&0xffffffff)
            assert n.calls==['allocate','enqueue','free'] and not n.queued
            assert bytes(n.u.mem_read(release.BUFFER,0x38))==msg
            results.append({'kind':kind,'case':'enqueue_failure','enqueue_status':enqueue,
                            'free_status':free,'result':-20,'native_free_attempted_once':True})
    return results


class Producer(ownership.Ownership):
    def __init__(self,cp,fail_at,mask,mode):
        super().__init__(cp,mask=mask,mode=mode,enabled=False)
        self.fail_at=fail_at
        self.attempts=0
        self.callbacks=0

    def code(self,u,pc,size,unused):
        if pc==0x565204:
            self.attempts+=1
            if self.attempts==self.fail_at:
                self.ret(5);return
        if pc==0x4e89f0:self.callbacks+=1
        super().code(u,pc,size,unused)


def producer_cases(cp,original):
    results=[]
    for mask in ownership.GROUPS:
        for mode in (0,1):
            for art in (False,True):
                types=[1,3,2] if art else [1,2]
                for fail_at in range(1,len(types)+1):
                    pair=[]
                    for image in (original,cp):
                        n=Producer(image,fail_at,mask,mode)
                        for address in (v.STATE,v.DESC,v.RES):v.put(n.u,address,0)
                        n.u.mem_write(v.PENDING,b'\0')
                        n.apply(art)
                        assert n.attempts==0 and v.word(n.u,v.STATE)==1
                        n.apply(art)
                        assert n.callbacks==0
                        pair.append((n,[struct.unpack_from('<I',msg)[0] for msg in n.queued]))
                    old,old_types=pair[0];new,new_types=pair[1]
                    assert old_types==types[:fail_at-1]+types[fail_at:]
                    assert old.attempts==len(types)
                    assert v.word(old.u,v.STATE)==2 and old.u.mem_read(v.PENDING,1)==b'\1'
                    assert new_types==types[:fail_at-1] and new.attempts==fail_at
                    assert v.word(new.u,v.STATE)==0 and new.u.mem_read(v.PENDING,1)==b'\0'
                    assert v.word(new.u,v.DESC)==0
                    assert v.word(new.u,v.RES)==ownership.OWNER
                    results.append({'mask':mask,'mode':mode,'art':art,'failed_message':types[fail_at-1],
                                    'parent_queued':old_types,'patched_queued':new_types,
                                    'patched_pending':0,'patched_state':0,'reservation_retained':True,
                                    'earlier_messages_still_queued':bool(new_types)})
    return results


def main():
    cp,r=build.make()
    original=bytearray(cp)
    for p in r['patches']:original[p['offset']:p['offset']+p['length']]=bytes.fromhex(p['before'])
    failures=[]
    for kind in (1,2,3):
        n=Queue(bytes(original),allocation=5)
        assert n.construct(kind)==0 and n.calls==['allocate'] and not n.queued
        failures.append({'kind':kind,'returned_success_without_enqueue':True})
    cases=run(cp)
    producers=producer_cases(cp,bytes(original))
    # Successful messages and the existing enqueue/free error paths must be
    # identical to the parent, not only plausible when examined in isolation.
    for kind in (1,2,3):
        for enqueue,free in ((0,0),(1,0),(-1,0),(1,-1)):
            a=Queue(bytes(original),enqueue=enqueue,free=free)
            b=Queue(cp,enqueue=enqueue,free=free)
            assert a.construct(kind)==b.construct(kind)
            assert (a.calls,a.queued)==(b.calls,b.queued)
            assert a.u.mem_read(release.BUFFER,0x38)==b.u.mem_read(release.BUFFER,0x38)
    sha=build.parent.b.sha
    report={'status':'NATIVE_QUEUE_ALLOCATION_FAILURE_FIXED_OFFLINE_NOT_FLASHABLE','camera_io':False,
            'recipe_sha256':sha((build.OUT/'recipe.json').read_bytes()),
            'in_memory_cp_sha256':r['in_memory_cp_sha256'],
            'original_counterexamples':failures,'cases':cases,'parent_equivalence_cases':12,
            'native_producer_failure_cases':producers,
            'source_sha256':{name:sha((build.HERE/name).read_bytes()) for name in
                             ('verify_queue_allocation_guard.py','verify_resource_release.py','verify_lut_ownership.py')},
            'limitations':['OS allocation, enqueue and free return values are fixtures.',
                           'Native constructors and queue helper execute; no actual OS ownership transfer or DMA is modeled.',
                           'Free failure is still reported as -20; native cleanup failure is not repaired here.',
                           'Native application clears its pending/state after partial-batch failure while earlier accepted messages remain queued.',
                           'No reader tokens or producer descriptor-snapshot guard have been connected yet.']}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'cases':len(cases),'equivalence_cases':12,
                      'native_producer_cases':len(producers)}))


if __name__=='__main__':main()
