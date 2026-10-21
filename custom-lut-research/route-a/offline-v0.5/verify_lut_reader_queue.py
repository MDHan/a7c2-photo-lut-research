"""Execute native type-1/type-3 workers after a partial producer failure.

The OS, MMIO, DMA submission and completion timing remain explicit fixtures.
"""
import json
import struct
from pathlib import Path
import build_queue_allocation_guard as build
import verify_queue_allocation_guard as queue
import verify_queue_completion as worker

v=queue.v


class Reader(worker.Worker):
    def __init__(self,cp,mode,message):
        super().__init__(cp,mode)
        self.message=message
        self.kind=struct.unpack_from('<I',message)[0]
        self.source=struct.unpack_from('<I',message,20)[0]
        self.descriptors=[]
        self.u.mem_write(worker.release.BUFFER,message)
        self.u.mem_write(v.PENDING,b'\0')
        v.put(self.u,v.STATE,0)
        v.put(self.u,v.DESC,0)

    def code(self,u,pc,size,unused):
        args=[u.reg_read(v.reg(i)) for i in range(4)]
        if pc==0x5353f4:
            assert args[1]==worker.DMA_DESC
            channel,count,entries=struct.unpack('<3I',u.mem_read(args[0],12))
            assert channel==4
            if self.kind==1:
                assert count==48
                rows=[struct.unpack('<3I',u.mem_read(entries+i*0x8c,12)) for i in range(count)]
                assert all(row[1:]==(0x408,1) for row in rows[::2])
                assert rows[1::2]==[(self.source+i*2000,0x3000,500) for i in range(24)]
                self.descriptors.extend(rows[1::2])
            else:
                assert self.kind==3 and count==1
                row=struct.unpack('<3I',u.mem_read(entries,12))
                assert row==(self.source,0x400,31)
                self.descriptors.append(row)
            self.timeline.append('dma_descriptor_boundary')
            self.ret();return
        if pc in (0xb82db6,0xb82e56):
            self.worker_result=args[0]
            self.timeline.append('handler_return')
        if (0xb82d7c<=pc<0xb82dbe or 0xb82e00<=pc<0xb82e5a or
                0xb8336c<=pc<0xb833f4):return
        super().code(u,pc,size,unused)

    def dispatch_message(self):
        self.call(0x53533c,worker.release.BUFFER)


def main():
    cp,r=build.make()
    producer=queue.Producer(cp,3,15,0)
    for address in (v.STATE,v.DESC,v.RES):v.put(producer.u,address,0)
    producer.u.mem_write(v.PENDING,b'\0')
    producer.apply(True);producer.apply(True)
    assert [struct.unpack_from('<I',m)[0] for m in producer.queued]==[1,3]
    assert v.word(producer.u,v.STATE)==0 and producer.u.mem_read(v.PENDING,1)==b'\0'
    cases=[]
    for message in producer.queued:
        assert struct.unpack_from('<I',message,12)[0]==0
        for mode in ('success','dma_error','timeout','initial_wait_failure','registration_failure','submission_failure'):
            n=Reader(cp,mode,message)
            n.dispatch_message()
            assert not n.callback_results
            expected=0 if mode in ('success','dma_error') else (-7 if mode=='timeout' else -20)
            assert n.worker_result==expected&0xffffffff
            assert n.u.mem_read(v.PENDING,1)==b'\0' and v.word(n.u,v.STATE)==0
            assert v.word(n.u,worker.CALLBACK_GLOBAL)==0
            cases.append({'message_type':n.kind,'mode':mode,'handler_result':expected,
                          'application_callbacks':n.callback_results,
                          'source':hex(n.source),'source_bytes':sum(row[2]*4 for row in n.descriptors),
                          'timeline':n.timeline,'pending_zero_before_and_after_dispatch':True})
    report={'status':'NATIVE_DATA_READERS_EXECUTED_OFFLINE_NOT_FLASHABLE','camera_io':False,
            'in_memory_cp_sha256':r['in_memory_cp_sha256'],
            'queue_guard_recipe_sha256':build.parent.b.sha((build.OUT/'recipe.json').read_bytes()),
            'source_sha256':{name:build.parent.b.sha((build.HERE/name).read_bytes()) for name in
                             ('verify_lut_reader_queue.py','verify_queue_allocation_guard.py',
                              'verify_queue_completion.py','verify_resource_release.py','verify_lut_ownership.py')},
            'cases':cases,
            'findings':['After the final allocation fails, native type-1/type-3 messages already accepted remain eligible for dispatch despite application pending/state being zero.',
                        'Actual user-LUT data messages have null application callbacks; only the later type-2 configuration message receives the application callback.',
                        'Both data handlers return zero after an injected DMA error completion because the wait succeeds; there is no application callback carrying that error.'],
            'limitations':['Sequential harness preserves messages from a real native producer path; OS scheduling and transport are not executed.',
                           'Descriptor generation executes native code; physical translation/cache maintenance and DMA are fixtures.',
                           'Timeout and completion ordering is controlled by the test; no real hardware cancellation or reachability claim.',
                           'This report does not connect reader protection or repair DMA error propagation.']}
    out=build.HERE/'lifecycle-dev/lut-reader-queue.json'
    out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'native_reader_cases':len(cases)}))


if __name__=='__main__':main()
