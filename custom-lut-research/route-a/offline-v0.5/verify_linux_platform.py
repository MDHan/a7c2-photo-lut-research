"""Verify native Linux platform code offline and bind evidence to dev-menu-03."""
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_INTR
from unicorn import arm64_const as a
from install_transaction import Package,PROGRAMS,digest
from native_pair_backend import FixedWindows
from native_pair_report import decode_receipt
from test_linux_platform import PlatformTests,Kernel,Services
import test_native_pair_core as core

HERE=Path(__file__).resolve().parent
OUT=HERE/'installer-evidence'


def syscall_abi(obj):
    with obj.open('rb') as f:
        elf=ELFFile(f);text=elf.get_section_by_name('.text').data()
        sym=next(s for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name=='lp_linux_syscall')
        start,size=sym['st_value'],sym['st_size']
        undefined=[s.name for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name and s['st_shndx']=='SHN_UNDEF']
        assert not undefined
        for section in elf.iter_sections():
            if section.name=='.rela.text':
                assert all(not start<=r['r_offset']<start+size for r in section.iter_relocations())
    cases=[]
    for nr,result in ((56,7),(67,-4),(68,-5),(40,0),(80,0),(82,-5)):
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);base,stop=0x100000,0x200000
        u.mem_map(base,(len(text)+4095)&~4095);u.mem_write(base,text);u.mem_map(stop,4096)
        values=[0x5555,nr,11,22,33,44,55,66]
        for i,value in enumerate(values):u.reg_write(getattr(a,'UC_ARM64_REG_X'+str(i)),value)
        u.reg_write(a.UC_ARM64_REG_LR,stop);seen=[]
        def interrupt(u,no,_):
            assert no==2 and u.reg_read(a.UC_ARM64_REG_X8)==nr
            actual=[u.reg_read(getattr(a,'UC_ARM64_REG_X'+str(i))) for i in range(6)]
            assert actual==values[2:];seen.append(actual)
            u.reg_write(a.UC_ARM64_REG_X0,result&((1<<64)-1))
        u.hook_add(UC_HOOK_INTR,interrupt)
        u.emu_start(base+start,stop,count=100)
        assert u.reg_read(a.UC_ARM64_REG_PC)==stop and len(seen)==1
        assert u.reg_read(a.UC_ARM64_REG_X0)==result&((1<<64)-1)
        cases.append({'number':nr,'arguments':seen[0],'raw_return':result})
    return {'code_size':len(text),'undefined_symbols':undefined,'syscall_instruction_cases':cases,
            'deployable_shared_object':False}


def main():
    names=('native/linux_platform.c','native/linux_platform.h','native/pair_core.c','native/pair_core.h','native/sha256.h',
           'test_linux_platform.py','test_native_pair_core.py','verify_linux_platform.py','native_pair_report.py','native_write_order.py','native_pair_backend.py','install_transaction.py')
    sources={n:digest((HERE/n).read_bytes()) for n in names}
    proc=subprocess.run([sys.executable,str(HERE/'test_linux_platform.py')],text=True,capture_output=True,check=True)
    log=proc.stdout+proc.stderr;assert 'Ran 6 tests' in log and '\nOK\n' in log
    (OUT/'linux-platform-tests.log').write_text(log)
    obj=OUT/'linux-platform.o'
    command=['/usr/bin/clang','-target','aarch64-none-elf','-std=c11','-O2','-ffreestanding','-fno-builtin',
             '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror',
             '-c',str(HERE/'native/linux_platform.c'),'-o',str(obj)]
    subprocess.run(command,capture_output=True,check=True)
    abi=syscall_abi(obj)
    package=Package(HERE/'package-dev-menu-03')
    fixed=FixedWindows(package,(HERE/'dev-menu-03/manifest.json').read_bytes())
    before=[package.files[n]['baseline'] for n in PROGRAMS];after=[package.files[n]['candidate'] for n in PROGRAMS]
    executions=[];PlatformTests.setUpClass()
    try:
        with tempfile.TemporaryDirectory(prefix='lut-platform-full-pair-') as directory:
            k=Kernel(Path(directory),before)
            state=c.create_string_buffer(PlatformTests.lib.platform_size())
            PlatformTests.lib.lp_linux_init(state,c.byref(k.services));io=PlatformTests.lib.platform_io(state)
            for action,source,target,order in [('INSTALL',before,after,fixed.install_order),('RESTORE',after,before,list(reversed(fixed.install_order)))]:
                plan=core.make_plan(source,target,order)
                operation=digest(('OFFLINE_LINUX_PLATFORM:'+package.key+':'+action).encode())
                plan.operation_id[:]=bytes.fromhex(operation)
                report=core.Report();workspace=core.Workspace();k.events.clear()
                PlatformTests.lib.lp_run(c.byref(plan),io,c.byref(workspace),c.byref(report))
                assert not k.errors and not k.fds and not k.quiesced and k.ro
                current=[p.read_bytes() for p in k.paths];assert current==target
                assert [p.stat().st_ino for p in k.paths]==k.initial_inodes
                receipt=decode_receipt(bytes(report),operation,{n:digest(source[i]) for i,n in enumerate(PROGRAMS)},
                                      {n:digest(target[i]) for i,n in enumerate(PROGRAMS)})
                assert receipt['outcome']=='written'
                writes=[list(e[1:]) for e in k.events if isinstance(e,tuple) and e[0]=='write']
                assert writes==[list(row) for row in order]
                remounts=[e[1] for e in k.events if isinstance(e,tuple) and e[0]=='remount']
                assert remounts==[0xc30,0xc31]
                executions.append({'action':action,'operation_id':operation,'write_callbacks':writes,
                                   'full_file_hashes':{n:digest(current[i]) for i,n in enumerate(PROGRAMS)},
                                   'inodes_preserved':True,'mount_calls':remounts,'all_descriptors_closed':True})
    finally:PlatformTests.tearDownClass()
    assert sources=={n:digest((HERE/n).read_bytes()) for n in names}
    report={'status':'LINUX_PLATFORM_OFFLINE_VERIFIED_QUIESCENCE_AND_LOADER_INCOMPLETE','camera_io':False,
            'candidate_flash_ready':False,'package_sha256':package.key,'candidate_sha256':package.expected('candidate'),
            'source_hashes':sources,'test_log_sha256':digest(log.encode()),'unit_tests':6,
            'cross_compile':{'command':command,'object_sha256':digest(obj.read_bytes()),**abi},
            'native_full_pair':executions,
            'mount_profile':{'usr':'/dev/nflasha15 ext2 ro','cp':'/dev/nflasha8 vfat rw','only_remounted':'/usr'},
            'boundaries':['Linux ownership/stat/mount and quiescence behavior are kernel fixtures.',
                          'File opens, nofollow, pread/pwrite, flock, fsync and close use real temporary POSIX files.',
                          'No camera quiescence implementation; missing callbacks reject before syscalls.',
                          'No linked shared module, activation/cache protocol, settings/WBI or report transport.'],
            'references':['https://raw.githubusercontent.com/torvalds/linux/v3.10/arch/arm64/include/uapi/asm/fcntl.h',
                          'https://raw.githubusercontent.com/torvalds/linux/v3.10/include/uapi/asm-generic/stat.h',
                          'https://raw.githubusercontent.com/torvalds/linux/v3.10/include/uapi/asm-generic/unistd.h']}
    (OUT/'linux-platform-verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'unit_tests':6,'native_pair_operations':len(executions),'syscall_abi_cases':len(abi['syscall_instruction_cases']),'camera_io':False}))

if __name__=='__main__':main()
