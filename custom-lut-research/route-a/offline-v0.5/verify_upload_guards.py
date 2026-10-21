"""Regression tests for real dev-menu-03 AP hooks; no camera interfaces."""
import itertools
import json
import struct
import tempfile
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as a
import build as b
import build_upload_guards as builder
import verify as v
import verify_lut_upload as old
import verify_menu as menu
from restore_baseline import restore

HERE = Path(__file__).resolve().parent
FOLDER = HERE / 'dev-menu-03'


class Guarded(old.Upload):
    def code(self, u, pc, size, data):
        if self.guard_start <= pc < self.guard_end:
            return
        super().code(u, pc, size, data)

    def __init__(self, ap, manifest, payload, fault=None, special=False):
        self.guard_start = manifest['upload_guards']['code_start']
        self.guard_end = manifest['upload_guards']['code_end']
        super().__init__(ap, payload, fault, special)

    def execute(self, system=2, pp=12, lut=3, exists=1):
        self.task(0x311a63c, system, pp, lut, exists)
        ptr = self.run(0x2887b48)
        self.write(ptr + lut - 3, bytes([int(self.special)]))
        self.timeline.clear(); self.messages.clear()
        assert self.run(0x34289a8, (menu.RAM + 0x4000,), old.RANGES) == 1
        assert len(self.messages) == 1
        return self.messages[0]


def standalone(ap, m, bias, size, special, result=1, unknown=False):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mapped = set()
    def write(address, data):
        for page in range(address & ~4095, (address+len(data)+4095)&~4095, 4096):
            if page not in mapped: u.mem_map(page,4096); mapped.add(page)
        u.mem_write(address, data)
    start,end = m['upload_guards']['code_start'],m['upload_guards']['code_end']
    write(bias+start, ap[start:end])
    write(bias+0x3428600, bytes(4))
    write(bias+0x5b7e8f8, struct.pack('<Q', bias+0x90fcb08))
    write(bias+0x5b8f438, struct.pack('<Q', bias+0x88f0b08))
    pointer = 0x77 if unknown else bias+(0x90fcb08 if special else 0x88f0b08)
    write(menu.RAM, struct.pack('<IIQ', size,0,pointer))
    write(menu.STACK, bytes(4096))
    saved = {menu.X(i):0x88220000+i for i in range(19,30)}
    saved[menu.X(20)] = menu.RAM
    for reg,val in saved.items():u.reg_write(reg,val)
    u.reg_write(menu.X(0),result); u.reg_write(a.UC_ARM64_REG_SP,menu.STACK+4000)
    u.emu_start(bias+start,bias+0x3428600,count=200)
    assert u.reg_read(a.UC_ARM64_REG_PC)==bias+0x3428600
    assert all(u.reg_read(reg)==val for reg,val in saved.items())
    expected = bool(result & 255) and not unknown and size >= (48124 if special else 48000)
    assert bool(u.reg_read(menu.X(0)) & 255) == expected
    assert bool(u.reg_read(a.UC_ARM64_REG_NZCV) & (1<<30)) == (not expected)
    return {'bias':hex(bias),'size':size,'special':special,'read_result':result,'unknown_buffer':unknown,'allowed':expected}


def mapping_rebased(ap,m,bias,mode):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); mapped=set()
    def write(addr,data):
        for page in range(addr&~4095,(addr+len(data)+4095)&~4095,4096):
            if page not in mapped:u.mem_map(page,4096);mapped.add(page)
        u.mem_write(addr,data)
    start,end=m['upload_guards']['code_start'],m['upload_guards']['code_end']
    write(bias+start,ap[start:end])
    for at in (0x34d37e8,0x165f430):write(bias+at,bytes(4))
    write(menu.RAM,bytes(64));write(menu.STACK,bytes(4096));write(menu.STOP,bytes(4))
    saved={menu.X(i):0x88220000+i for i in range(19,30)}
    for r,val in saved.items():u.reg_write(r,val)
    u.reg_write(menu.X(0),menu.RAM+48);u.reg_write(menu.X(1),menu.RAM)
    u.reg_write(a.UC_ARM64_REG_SP,menu.STACK+4000);u.reg_write(a.UC_ARM64_REG_LR,menu.STOP)
    calls=[]
    def hook(u,pc,size,_):
        if pc==bias+0x34d37e8:
            calls.append('map')
            assert u.reg_read(menu.X(1))==menu.RAM
            raw=(1<<64)-1 if mode.startswith('mmap') else 0x70000000
            result=struct.pack('<QIiQIII',raw,0xc000,-1 if mode=='open_fail' else 12,raw,0xc000,0,2 if mode=='open_fail' else 0)
            write(menu.RAM,result)
        elif pc==bias+0x165f430:
            calls.append('close')
            assert u.reg_read(menu.X(0))==12
            u.reg_write(menu.X(0),0xffffffff if mode=='mmap_close_fail' else 0)
        else:
            assert bias+start<=pc<bias+end,hex(pc)
            return
        u.reg_write(a.UC_ARM64_REG_PC,u.reg_read(a.UC_ARM64_REG_LR))
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(bias+m['upload_guards']['symbols']['lut_checked_mapping'],menu.STOP,count=200)
    assert u.reg_read(a.UC_ARM64_REG_PC)==menu.STOP
    assert u.reg_read(a.UC_ARM64_REG_SP)==menu.STACK+4000
    assert all(u.reg_read(reg)==val for reg,val in saved.items())
    status=struct.unpack('<I',u.mem_read(menu.RAM+32,4))[0]
    assert status==(0 if mode=='valid' else 2)
    assert calls==(['map','close'] if mode.startswith('mmap') else ['map'])
    if mode.startswith('mmap'):
        assert bytes(u.mem_read(menu.RAM,12))==bytes(12)
        assert struct.unpack('<i',u.mem_read(menu.RAM+12,4))[0]==-1
    return {'bias':hex(bias),'mode':mode,'calls':calls,'result_status':status}


def main():
    m=json.loads((FOLDER/'manifest.json').read_text())
    ap=(FOLDER/'candidate/appFw.so').read_bytes(); cp=(FOLDER/'candidate/cpapp-b.bin').read_bytes()
    structural=v.structural(FOLDER,m)
    with tempfile.TemporaryDirectory(prefix='lut-guards-audit-') as tmp:
        rebuilt=builder.build(Path(tmp)/'rebuilt')
        assert rebuilt['outputs']==m['outputs'] and rebuilt['patches']==m['patches']
        assert restore(FOLDER,Path(tmp)/'restored')==b.HASHES
    original=(HERE/'dev-menu-02/candidate/appFw.so').read_bytes()
    cases=[]
    # Compare successful native messages in both still and movie modes.
    for system,pp,lut,special in itertools.product((2,3),range(12,16),(3,18),(False,True)):
        data=bytes((i*17+3)%256 for i in range(48128 if special else 48000))
        new=Guarded(ap,m,data,special=special); message=new.execute(system,pp,lut)
        baseline=Guarded(original,m,data,special=special); expected=baseline.execute(system,pp,lut)
        assert message==expected and new.timeline==baseline.timeline
        assert new.copies==[b.sha(data)]
        got=old.receive(cp,message)
        capture=old.capture_boundary(cp,got)
        assert capture['stops']==(['0x54e398'] if special else ['0x54e15c'])
        cases.append({'system':system,'pp':pp,'lut':lut,'special':special,'message_equal_dev02':True,'capture_boundary':capture['stops'][0]})
    failures=[]
    for system,special,length in itertools.product((2,3),(False,True),(0,1,17,47999,48000,48123,48124,48128,49152)):
        data=bytes(length)
        h=Guarded(ap,m,data,special=special); msg=h.execute(system)
        received=old.receive(cp,msg)
        valid=length >= (48124 if special else 48000)
        if valid:
            assert h.transfer is not None and len(h.copies)==1
        else:
            assert h.transfer is None and not h.copies and 'mmap' not in h.timeline
            assert received['descriptor']==[0]*6
            capture=old.capture_boundary(cp,received)
            assert capture['terminal']=='0x48c778' and capture['error']=='0xc17e0001'
        failures.append({'system':system,'special':special,'length':length,'uploaded':valid,'cp_cleared':not valid})
    faults=[]
    for fault in ('file_open','missing_source','missing_target','capacity','map_open','mmap','munmap','map_close','transfer'):
        h=Guarded(ap,m,bytes(48128),fault,special=True); msg=h.execute()
        assert old.receive(cp,msg)['descriptor']==[0]*6
        assert 'invalid_map_destination' not in h.timeline
        if fault=='mmap':
            assert h.timeline.count('close_mapping')==1 and 'munmap' not in h.timeline
            assert h.transfer is None and not h.copies
        faults.append({'fault':fault,'timeline':h.timeline,'cp_cleared':True})
    rebased=[standalone(ap,m,bias,length,special,result,unknown)
             for bias,length,special,result,unknown in itertools.product(
                 (0,0x10000000,0x7100000000),(0,17,47999,48000,48123,48124,48128),(False,True),(0,1),(False,True))]
    maps=[mapping_rebased(ap,m,bias,mode) for bias,mode in itertools.product(
        (0,0x10000000,0x7100000000),('valid','open_fail','mmap_fail','mmap_close_fail'))]
    assert v.structural(FOLDER,m)==structural
    sources=('verify_upload_guards.py','verify_lut_upload.py','verify_menu.py','verify.py','build.py','build_upload_guards.py','lut_upload_guards.S','restore_baseline.py')
    report={'status':'NOT_READY_TO_FLASH','camera_io':False,'structural':structural,
            'rebuild_byte_identical':True,'inverse_to_FL23_verified':True,
            'valid_comparisons':cases,'length_cases':failures,'fault_cases':faults,
            'rebased_length_cases':rebased,'rebased_mapping_cases':maps,
            'source_hashes':{name:b.sha((HERE/name).read_bytes()) for name in sources},
            'limits':['Minimum byte coverage is not format/content integrity validation.',
                      'Libc, interchip completion and CP object services are offline fixtures.',
                      'Concurrency, CP lifetime, full event loop and camera installer remain incomplete.',
                      'close is attempted once on MAP_FAILED; close failure does not prove descriptor cleanup.']}
    (FOLDER/'upload-guard-verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'valid':len(cases),'length':len(failures),'faults':len(faults),'rebased_length':len(rebased),'rebased_mapping':len(maps),'status':report['status']}))

if __name__=='__main__':main()
