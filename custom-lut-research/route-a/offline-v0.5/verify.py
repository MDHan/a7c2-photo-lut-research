"""Verify actual patched files; keep native boundaries separate from mocks."""
import argparse, importlib.metadata, io, itertools, json, struct, sys
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as ar, arm64_const as aa
import build as b
sys.path.insert(0,str(b.HERE.parent))
import emulate_parameter_route as n
RAM,STACK,STOP=n.RAM,n.STACK,n.STOP
G,STATE,DESC,TOKEN,PENDING,RES=0x165a720,0x1a6aefc,0x1a6af00,0x1a6af10,0x1b1e235,0x1a7e608
RAW=[RAM+0x2000+i*0x400 for i in range(4)]
MODULE,STAGE,PARAM=RAM+0x1000,RAM+0x4000,0x77
SP=STACK+0xff00
word=lambda u,a:struct.unpack('<I',u.mem_read(a,4))[0]
put=n.put32
reg=lambda i:getattr(ar,'UC_ARM_REG_R'+str(i))

def structural(folder,m):
    assert m['inputs']==b.HASHES and set(m['outputs'])==set(b.HASHES)
    report={}
    for name,spec in m['outputs'].items():
        raw=(folder/'candidate'/name).read_bytes()
        assert len(raw)==spec['size'] and b.sha(raw)==spec['sha256']
        undo=bytearray(raw)
        for p in m['patches']:
            if p['file']!=name:continue
            at=p['offset'];end=at+p['length']
            assert raw[at:end]==bytes.fromhex(p['after'])
            undo[at:end]=bytes.fromhex(p['before'])
        # This proves there are NO changes outside the manifest, and restores
        # exactly the previous FL23 image, not an invented rollback version.
        assert b.sha(undo)==m['inputs'][name]
        assert b.sha((b.BASE/name).read_bytes())==m['inputs'][name]
        old=(b.BASE/name).read_bytes()
        report[name]={'sha256':b.sha(raw),'inverse_patch_matches_baseline':True,
                      'changed_bytes':sum(a!=z for a,z in zip(old,raw)),
                      'declared_regions':sum(p['file']==name for p in m['patches'])}
    e=ELFFile(io.BytesIO((folder/'candidate/appFw.so').read_bytes()))
    s=e.get_segment(0);assert s['p_flags']==5 and s['p_filesz']==s['p_memsz']==b.AP_CODE+m['placement']['ap_bytes']
    return report

def ap_run(raw,args,bias=0):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for page in (0x352c000,0x4c7d000,b.AP_CODE&~4095):
        u.mem_map(bias+page,0x1000);u.mem_write(bias+page,raw[page:page+0x1000])
    for page in (RAM,STACK):u.mem_map(page,0x10000)
    u.mem_map(STOP,0x1000)
    for i,v in enumerate(args[:8]):u.reg_write(getattr(aa,'UC_ARM64_REG_X'+str(i)),v)
    preserved={getattr(aa,'UC_ARM64_REG_X'+str(i)):0x12340000+i for i in range(19,30)}
    for r,v in preserved.items():u.reg_write(r,v)
    u.reg_write(aa.UC_ARM64_REG_SP,SP);u.reg_write(aa.UC_ARM64_REG_LR,STOP)
    u.mem_write(SP,struct.pack('<QQ',args[8],RAM));u.mem_write(RAM,b'\xa5'*64)
    n.execute(u,bias+b.AP_ENTRY,[(bias+b.AP_ENTRY,bias+0x352c790),(bias+b.AP_CODE,bias+b.AP_CODE+60)])
    assert u.reg_read(aa.UC_ARM64_REG_SP)==SP
    assert all(u.reg_read(r)==v for r,v in preserved.items())
    data=bytes(u.mem_read(RAM,64));assert data[:8]==b'\xa5'*8 and data[13:]==b'\xa5'*51
    return data[8:13]

def ap_matrix(ap):
    count=eligible=0
    for lut,exists,log,pp,mode,cinematic in itertools.product((0,1,2,3,18,19,255),(0,1),(0,1,2,3),(0,11,12,15,16),(0,1),(0,1)):
        args=(lut,exists,log,0,0,pp,mode,cinematic,0)
        scoped=mode==0 and 3<=lut<=18 and exists==1 and log==0 and 12<=pp<=15 and cinematic==1
        reference=list(args)
        if scoped:reference[6]=1;eligible+=1
        # Execute the actual baseline builder for each expected message.
        expected,_=n.ap_message(reference)
        assert ap_run(ap,args)==expected,args
        count+=1
    rebased=0
    for bias,lut,pp,inp,gamut in itertools.product((0x10000000,0x7100000000),(0,3,18,19),(11,12,15,16),(0,1),(0,1)):
        args=(lut,1,0,inp,gamut,pp,0,1,0)
        reference=list(args)
        if 3<=lut<=18 and 12<=pp<=15:reference[6]=1
        assert ap_run(ap,args,bias)==n.ap_message(reference)[0]
        rebased+=1
    return {'native_baseline_comparisons':count,'eligible_cases':eligible,'nonzero_load_bias_cases':rebased}

def boot_map(cp,length,physical_bias=0):
    # Execute the ORIGINAL ARM page-table constructor, no MMIO/CP15 stubs.
    u=n.cp_machine();u.mem_write(0x108000,cp)
    l1,l2=RAM,RAM+0x4000
    u.mem_write(l1,struct.pack('<4096I',*[0x10c12+(i<<20) for i in range(4096)]))
    put(u,0x108f1c,l1);put(u,0x108d98,l2);put(u,0x108d9c,0)
    for i,v in enumerate((0x128000,length,0x128000+physical_bias,15)):u.reg_write(reg(i),v)
    u.reg_write(ar.UC_ARM_REG_LR,STOP);u.reg_write(ar.UC_ARM_REG_CPSR,0x13)
    def code(u,a,s,_):assert 0x108768<=a<0x108974,hex(a)
    def write(u,t,a,s,v,_):assert (RAM<=a and a+s<=RAM+0x10000) or (STACK<=a and a+s<=STACK+0x10000) or a==0x108d9c,hex(a)
    u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write)
    u.emu_start(0x108768,STOP,count=250000)
    assert u.reg_read(ar.UC_ARM_REG_PC)==STOP
    pde=word(u,l1+(b.CP_CODE>>20)*4)
    assert pde&3==1
    pte=word(u,(pde&~0x3ff)+((b.CP_CODE>>12)&255)*4)
    assert pte&3==2 # small page, XN bit clear
    assert pte&0xfffff000==(b.CP_CODE+physical_bias)&0xfffff000
    return bytes(u.mem_read(RAM,0x10000)),{'pte':hex(pte),'executable':True,'physical_bias':hex(physical_bias)}

def mapping_cases(cp,m):
    results=[]
    for bias in (0,0xd0220000):
        before,_=boot_map(cp,0xb07490,bias)
        after,r=boot_map(cp,m['placement']['cp_text_length'],bias)
        assert before==after
        results.append({**r,'page_tables_equal_baseline':True,'native_constructor_executed':True})
    return results

class Capture:
    def __init__(self,cp,m,mask=1):
        self.u=n.cp_machine();u=self.u;u.mem_write(0x108000,cp);self.m=m
        self.result=SP+0x4c;self.args=(self.result,MODULE,PARAM,STAGE,*RAW)
        for i,v in enumerate(self.args[:4]):u.reg_write(reg(i),v)
        u.mem_write(SP,struct.pack('<4I',*RAW))
        self.saved={reg(i):0x11800000+i for i in range(4,12)}
        for r,v in self.saved.items():u.reg_write(r,v)
        put(u,MODULE+0x24,0x8833)
        for a,v in [(G+0xaf8,10),(G+0xafc,0),(G+0xb00,0),(G+0xb04,1),(G+0xb08,0),
                    (G+0x68,0x7000000),(G+0x70,0x7100000),(G+0x78,0xbb80),(G+0x7c,0x7c),
                    (G+0xc0,0x123),(G+0x684,17),(STATE,2),(DESC,9),(TOKEN,0x123)]:put(u,a,v)
        u.mem_write(PENDING,b'\0')
        for i,a in enumerate(RAW):
            # Guard unrelated descriptor fields against accidental mutation.
            u.mem_write(a,bytes((j*7+i)%256 for j in range(0x320)))
            put(u,a+0x1c8,0x10000 if mask&(1<<i) else 0);put(u,a+0x234,0)
        self.original=[bytes(u.mem_read(a,0x320)) for a in RAW]

    def run(self,stop=(0x480f28,0x5f4144,0xbb2bca,0x54e15c,0x54e398),model=None):
        u=self.u;out={'stops':[], 'model':model,'loads':0,'delays':0,'submits':0}
        ranges=[(b.CP_CODE,b.CP_CODE+self.m['placement']['cp_bytes']),
                (0x48c740,0x48c74e),(0x4e8a5c,0x4e8b22),(0xb31a54,0xb31aac),
                (0x4e876c,0x4e8970),(0x480f28,0x4810a6),(0x47b074,0x47b14a)]
        terminals=(0x48c778,0x48c790,0x48c74e)
        def ret(value=0):u.reg_write(reg(0),value&0xffffffff);u.reg_write(ar.UC_ARM_REG_PC,u.reg_read(ar.UC_ARM_REG_LR))
        def hook(u,a,size,_):
            if a in terminals:
                out['terminal']=hex(a);u.emu_stop();return
            if model and a==0x4e876c:
                # Explicit software protocol fixture ONLY: no driver success
                # is claimed. Strict boundary tests below run native code.
                out['loads']+=1
                if model=='acquire_failure':put(u,STATE,0)
                elif word(u,STATE)!=1:put(u,STATE,1);put(u,RES,word(u,MODULE+0x24))
                else:put(u,STATE,2);put(u,DESC,9);put(u,TOKEN,0x123);u.mem_write(PENDING,b'\1');put(u,RES,0)
                ret();return
            if model and a==0x5f4144:
                assert u.reg_read(reg(0))==20
                out['delays']+=1
                if model in ('async_success','submit_failure','callback_failure'):
                    u.mem_write(PENDING,b'\0')
                    if model=='callback_failure':put(u,STATE,0)
                if model=='settings_change':put(u,G+0x684,18)
                ret(-25 if model=='delay_failure' else 0);return
            if model and a==0x480f28:
                out['submits']+=1;self.check_args()
                out['submit_flags']=[word(u,a+0x234) for a in RAW]
                u.mem_write(self.result,struct.pack('<II',0 if model=='submit_failure' else 1,0x1234 if model=='submit_failure' else 0))
                ret();return
            if a in stop:
                out['stops'].append(hex(a));u.emu_stop();return
            if a in (0xb4457a,0xb4361c,0x47a7c0):ret();return # output-only logs
            assert any(lo<=a<hi for lo,hi in ranges),hex(a)
        def write(u,t,a,s,v,_):
            assert any(lo<=a and a+s<=hi for lo,hi in [(RAM,RAM+0x10000),(STACK,STACK+0x10000),(STATE,STATE+0x18),(PENDING,PENDING+1)]),hex(a)
        h=u.hook_add(UC_HOOK_CODE,hook);w=u.hook_add(UC_HOOK_MEM_WRITE,write)
        try:u.emu_start(b.CP_ENTRY|1,STOP,count=400000)
        finally:u.hook_del(h);u.hook_del(w)
        assert out['stops'] or 'terminal' in out,'instruction budget exhausted'
        out['error']=hex(word(u,self.result+4))
        if 'terminal' in out:
            assert u.reg_read(ar.UC_ARM_REG_SP)==SP
            assert all(u.reg_read(r)==v for r,v in self.saved.items()),'callee-saved register changed'
        for i,a in enumerate(RAW):
            now=bytearray(u.mem_read(a,0x320));now[0x234:0x238]=self.original[i][0x234:0x238]
            assert now==self.original[i],'descriptor fields other than MLUT changed'
        return out

    def check_args(self):
        u=self.u;sp=u.reg_read(ar.UC_ARM_REG_SP)
        actual=tuple(u.reg_read(reg(i)) for i in range(4))+struct.unpack('<4I',u.mem_read(sp,16))
        assert actual==self.args,(actual,self.args)

def capture_tests(cp,m):
    strict=[];protocol=[]
    for mask in range(1,16):
        c=Capture(cp,m,mask);r=c.run();assert r['stops']==['0x480f28'];c.check_args()
        assert [word(c.u,a+0x234) for a in RAW]==[int(bool(mask&(1<<i))) for i in range(4)]
        strict.append({'case':'ready','mask':mask,**r})
    for case in ('pending','acquire','load','artgen','non_user','inactive','bad_output','zero_size','bad_size','bad_artgen_size','missing_artgen','zero_owner'):
        c=Capture(cp,m,0 if case=='inactive' else 1);u=c.u
        if case=='pending':u.mem_write(PENDING,b'\1')
        if case in ('acquire','load','artgen'):put(u,STATE,0 if case=='acquire' else 1);put(u,RES,0x8833)
        if case=='load':put(u,G+0x7c,0)
        if case=='non_user':put(u,G+0xaf8,11)
        if case=='bad_output':put(u,RAW[0]+0x234,2);c.original[0]=bytes(u.mem_read(RAW[0],0x320))
        if case=='zero_size':put(u,G+0x78,0)
        if case=='bad_size':put(u,G+0x78,0xbb7f)
        if case=='bad_artgen_size':put(u,G+0x7c,0x7d)
        if case=='missing_artgen':put(u,G+0x70,0);put(u,G+0x74,0)
        if case=='zero_owner':put(u,MODULE+0x24,0)
        r=c.run()
        expected={'pending':'0x5f4144','acquire':'0xbb2bca','load':'0x54e15c','artgen':'0x54e398','non_user':'0x480f28','inactive':'0x480f28'}
        if case in expected:assert r['stops']==[expected[case]],(case,r)
        else:assert r.get('terminal')=='0x48c778' and r['error']=='0xc17e0001',(case,r)
        strict.append({'case':case,**r})
    # Retain the native module's own validation and reach its real OS lock.
    c=Capture(cp,m);r=c.run(stop=(0x5e23b4,));assert r['stops']==['0x5e23b4'];strict.append({'case':'native_module_lock',**r})
    for model in ('async_success','callback_failure','acquire_failure','pending_timeout','foreign_reservation','settings_change','delay_failure','submit_failure'):
        for mask in (1,3,15):
            c=Capture(cp,m,mask);u=c.u
            put(u,STATE,0)
            if model in ('pending_timeout','settings_change','delay_failure'):put(u,STATE,2);u.mem_write(PENDING,b'\1')
            if model=='foreign_reservation':put(u,STATE,1);put(u,RES,0x4455)
            r=c.run(model=model)
            if model=='async_success':
                assert r['terminal']=='0x48c790' and r['loads']==2 and r['delays']==1 and r['submits']==1,r
            elif model=='submit_failure':
                assert r['terminal']=='0x48c74e' and r['submits']==1 and r['error']=='0x1234',r
                assert all(word(u,a+0x234)==0 for a in RAW)
            else:
                assert r['terminal']=='0x48c778' and r['submits']==0,r
                code={'callback_failure':2,'acquire_failure':2,'pending_timeout':6,'foreign_reservation':6,'settings_change':3,'delay_failure':7}[model]
                assert r['error']==hex(0xc17e0000|code),r
                if model in ('pending_timeout','foreign_reservation'):assert r['delays']==150 and r['loads']==0,r
                if model=='foreign_reservation':assert word(u,RES)==0x4455
                if model=='pending_timeout':assert u.mem_read(PENDING,1)==b'\1'
                assert all(word(u,a+0x234)==0 for a in RAW)
            protocol.append({'case':model,'mask':mask,**r})
    return {'strict_native_boundary_cases':strict,'explicit_software_protocol_cases':protocol,
            'driver_scheduler_isp_or_jpeg_execution_proven':False}

def ap_to_capture(ap,cp,m):
    cases=[]
    for slot,pp,inp,gamut,registered in itertools.product((3,18),(12,15),(0,1),(0,1),(0,0x7c)):
        fields=ap_run(ap,(slot,1,0,inp,gamut,pp,0,1,0))
        assert fields==bytes([10,0,inp,int(gamut==0),0])
        c=Capture(cp,m);u=c.u
        u.mem_write(RAM+8,fields);u.reg_write(reg(0),RAM);u.reg_write(ar.UC_ARM_REG_LR,STOP|1)
        # Native receiver executes the actual message from the patched AP.
        h=u.hook_add(UC_HOOK_CODE,lambda u,a,s,d: None if 0x8db56e<=a<0x8db5d4 else (_ for _ in ()).throw(AssertionError(hex(a))))
        u.emu_start(0x8db56f,STOP,count=2000);u.hook_del(h)
        assert u.reg_read(ar.UC_ARM_REG_PC)==STOP
        assert word(u,G+0x684)==18
        put(u,G+0x7c,registered)
        expected=(9 if registered else 11) if inp==0 else (6 if registered else 15)
        # Hardware readiness remains an explicitly supplied precondition.
        put(u,DESC,expected)
        for i,v in enumerate(c.args[:4]):u.reg_write(reg(i),v)
        r=c.run();assert r['stops']==['0x480f28'];c.check_args()
        assert word(u,RAW[0]+0x234)==1
        cases.append({'slot':slot,'profile':pp,'input':inp,'gamut':gamut,'registered_fixture':registered,
                      'native_descriptor':expected,'ap_message':list(fields),'reaches_native_vfx':True})
    return cases

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);a=p.parse_args()
    m=json.loads((a.folder/'manifest.json').read_text())
    report={'status':'OFFLINE_VERIFIED_HARDWARE_UNVERIFIED','camera_io':False,'structural':structural(a.folder,m)}
    cp=(a.folder/'candidate/cpapp-b.bin').read_bytes();ap=(a.folder/'candidate/appFw.so').read_bytes()
    report['native_boot_mapping']=mapping_cases(cp,m)
    report['capture']=capture_tests(cp,m)
    report['ap_message_to_capture']=ap_to_capture(ap,cp,m)
    print('CP mapping, native boundaries and protocol checks passed',flush=True)
    report['ap']=ap_matrix(ap)
    report['verification_provenance']={'script_sha256':b.sha(Path(__file__).read_bytes()),
        'builder_sha256':b.sha((b.HERE/'build.py').read_bytes()),'python':sys.version,
        'dependencies':{x:importlib.metadata.version(x) for x in ('capstone','pyelftools','numpy','unicorn')},
        'candidate_sha256':{name:spec['sha256'] for name,spec in m['outputs'].items()}}
    (a.folder/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'ap':report['ap'],
                      'native_capture_cases':len(report['capture']['strict_native_boundary_cases']),
                      'explicit_protocol_cases':len(report['capture']['explicit_software_protocol_cases'])},indent=2))

if __name__=='__main__':main()
