"""Actual C Linux adapter + C pair core, with a bounded virtual kernel.

Only file operations map to real POSIX calls on temporary files. Ownership,
Linux stat ABI, mounts and application quiescence are explicit test fixtures.
"""
import ctypes as c
import errno
import fcntl
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
import test_native_pair_core as core

HERE=Path(__file__).resolve().parent
Sys=c.CFUNCTYPE(core.I64,c.c_void_p,*([core.I64]*7))
class Services(c.Structure):
    _fields_=[('context',c.c_void_p),('syscall',Sys),('enter',core.Fn0),('leave',core.Fn0)]


class Kernel:
    def __init__(self,root,before,fault=None):
        self.root,self.fault=root,fault
        for d in ('usr/lib','cp','tmp/jiritsu'):(root/d).mkdir(parents=True,exist_ok=True)
        self.paths=[root/'usr/lib/appFw.so',root/'cp/cpapp-b.bin']
        for p,data in zip(self.paths,before):p.write_bytes(data)
        self.initial_inodes=[p.stat().st_ino for p in self.paths]
        if fault=='leaf_symlink':
            p=self.paths[0];real=p.with_suffix('.saved');p.rename(real);p.symlink_to(real.name)
        if fault=='dir_symlink':
            p=root/'usr/lib';p.rename(root/'usr/saved');p.symlink_to('saved')
        self.fds={};self.nextfd=1000;self.ro=True;self.events=[];self.errors=[];self.quiesced=False;self.failed=False
        self.calls=0;self.short_reads=0;self.initial='sync,noatime,nodiratime,errors=continue'
        if fault=='policy_flags':self.initial='sync,nosuid,nodev,noexec,dirsync,noatime,nodiratime,errors=continue'
        self.callbacks=[Sys(self.safe_sys),core.Fn0(self.enter),core.Fn0(self.leave)]
        self.services=Services(None,*self.callbacks)
    def enter(self,_):
        self.events.append('quiesce_enter')
        if self.fault=='quiesce_enter':return -16
        self.quiesced=True;return 0
    def leave(self,_):
        self.events.append('quiesce_leave');self.quiesced=False
        return -5 if self.fault=='quiesce_leave' else 0
    def once(self,label):
        if self.fault==label and not self.failed:self.failed=True;return True
        return False
    def safe_sys(self,ctx,n,*args):
        try:return self.sys(n,*args)
        except OSError as e:return -e.errno
        except BaseException as e:self.errors.append(repr(e));return -99
    def snapshot(self):
        usr=f'/dev/nflasha15 /usr ext2 {"ro" if self.ro else "rw"},{self.initial} 0 0\n'
        cp='/dev/nflasha8 /cp vfat rw,sync,noatime,nodiratime,fmask=0022,dmask=0022 0 0\n'
        fault=self.fault
        if fault=='wrong_device':usr=usr.replace('nflasha15','nflasha99')
        if fault=='wrong_fs':usr=usr.replace('ext2','ext4')
        if fault=='duplicate_usr':usr+=usr
        if fault=='missing_cp':cp=''
        if fault=='cp_ro':cp=cp.replace(' rw,',' ro,')
        if fault=='duplicate_mode':usr=usr.replace('ext2 ','ext2 ro,')
        if fault=='unknown_usr_option':usr=usr.replace('errors=continue','new_option')
        if fault=='changed_cp_options' and not self.ro:cp=cp.replace('sync,','',1)
        data=(usr+cp).encode()
        if fault=='truncated_mounts':data=data[:-1]
        if fault=='oversized_mounts':data=b'x'*32768
        return data
    def sys(self,n,a,b,d,e,f,g):
        self.calls+=1
        if n==175:return 1 if self.fault=='not_root' else 0
        if n==56:
            name=c.string_at(b).decode();flags=d
            if name=='/proc/mounts':
                obj=io.BytesIO(self.snapshot());p=None
            else:
                assert flags & 32768 and flags & 524288
                assert not flags & (512|1024), 'no create/truncate firmware paths'
                if name=='/':p=self.root
                else:
                    assert a in self.fds and self.fds[a][0]=='dir'
                    assert '/' not in name and name not in ('.','..')
                    p=self.fds[a][2]/name
                if p in self.paths and flags&2:
                    assert self.quiesced and not self.ro
                    if self.once('changed_inode'):
                        tmp=p.with_suffix('.replacement');tmp.write_bytes(p.read_bytes());os.replace(tmp,p)
                native_flags=(os.O_RDWR if flags&2 else os.O_RDONLY)|os.O_NOFOLLOW
                if flags&16384:native_flags|=os.O_DIRECTORY
                if flags&64:
                    assert name=='a7c2.lut.pair.lock';native_flags|=os.O_CREAT
                obj=os.open(p,native_flags,e)
            fd=self.nextfd;self.nextfd+=1
            kind='mounts' if p is None else 'dir' if flags&16384 else 'file'
            self.fds[fd]=(kind,obj,p,flags);self.events.append(('open',str(p.relative_to(self.root)) if p else 'mounts',flags))
            return fd
        if n==57:
            kind,obj,p,flags=self.fds.pop(a)
            if kind=='mounts':obj.close()
            else:os.close(obj)
            if p in self.paths and flags&2 and self.once('file_close'):return -5
            return 0
        if n==80:
            kind,obj,p,flags=self.fds[a];assert kind!='mounts'
            st=os.fstat(obj);raw=bytearray(128)
            device=11 if p==self.root/'usr' or self.root/'usr' in p.parents else 12 if p==self.root/'cp' or self.root/'cp' in p.parents else 13
            mode=st.st_mode;uid=0;links=st.st_nlink
            if p in self.paths and self.fault=='file_device':device+=99
            if p in self.paths and self.fault=='hardlink':links=2
            if p.name=='a7c2.lut.pair.lock' and self.fault=='unsafe_lock':mode|=2
            struct.pack_into('<QQIIIIQQqIIQ',raw,0,device,st.st_ino,mode,links,uid,0,0,0,st.st_size,4096,0,0)
            c.memmove(b,bytes(raw),128);return 0
        if n==32:
            kind,obj,p,flags=self.fds[a];assert p.name=='a7c2.lut.pair.lock'
            if b==6 and self.fault=='lock_busy':return -11
            fcntl.flock(obj,fcntl.LOCK_EX|fcntl.LOCK_NB if b==6 else fcntl.LOCK_UN);return 0
        if n==63:
            kind,obj,p,flags=self.fds[a];assert kind=='mounts'
            if self.fault=='mount_read_eintr' and self.short_reads<2:self.short_reads+=1;return -4
            if self.fault=='mount_read_eintr_forever':return -4
            data=obj.read(min(d,17) if self.fault=='mount_short_read' else d)
            c.memmove(b,data,len(data));return len(data)
        if n==40:
            assert a==0 and c.string_at(b)==b'/usr' and d==0 and f==0 and self.quiesced
            assert e & ~1 == (0xcbe if self.fault=='policy_flags' else 0xc30)
            self.events.append(('remount',e))
            if not e&1 and self.fault=='remount_no_change':return 0
            self.ro=bool(e&1)
            if not self.ro and self.once('rw_error_after_change'):return -5
            if self.ro and self.fault=='restore_ro_failure':self.ro=False;return -5
            return 0
        if n in (67,68,82):
            kind,obj,p,flags=self.fds[a];assert kind=='file' and p in self.paths and self.quiesced
            if n==67:
                data=os.pread(obj,min(d,13) if self.fault=='file_short_io' else d,e);c.memmove(b,data,len(data));return len(data)
            if n==68:
                assert not self.ro and flags&2
                self.events.append(('write',self.paths.index(p),e,d))
                if self.once('partial_write'):
                    os.pwrite(obj,c.string_at(b,max(1,d//2)),e);return -5
                return os.pwrite(obj,c.string_at(b,min(d,13) if self.fault=='file_short_io' else d),e)
            os.fsync(obj);return -5 if self.once('fsync') else 0
        raise AssertionError(('unexpected syscall',n))


class PlatformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='lut-linux-platform-build-');root=Path(cls.tmp.name)
        wrapper=root/'test.c'
        wrapper.write_text('#include "linux_platform.h"\n'
                           'unsigned long platform_size(void){return sizeof(struct lp_linux);}\n'
                           'struct lp_io *platform_io(struct lp_linux *s){return &s->io;}\n')
        cls.libpath=root/'platform.dylib'
        subprocess.run(['clang','-std=c11','-O2','-DLP_HOST_TEST','-fno-builtin','-Wall','-Wextra','-Werror','-dynamiclib','-I',str(HERE/'native'),str(wrapper),str(HERE/'native/linux_platform.c'),str(HERE/'native/pair_core.c'),'-o',str(cls.libpath)],check=True,capture_output=True)
        cls.lib=c.CDLL(str(cls.libpath));cls.lib.platform_size.restype=c.c_ulong
        cls.lib.lp_linux_init.argtypes=[c.c_void_p,c.POINTER(Services)]
        cls.lib.platform_io.argtypes=[c.c_void_p];cls.lib.platform_io.restype=c.POINTER(core.IO)
        cls.lib.lp_run.argtypes=[c.POINTER(core.Plan),c.POINTER(core.IO),c.POINTER(core.Workspace),c.POINTER(core.Report)]
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='lut-linux-platform-test-');self.root=Path(self.tmp.name)
        self.before=[b'A'*128,b'C'*96];self.after=[b'A'*16+b'BBBB'+b'A'*108,b'X'*4+b'C'*92]
        self.plan=core.make_plan(self.before,self.after,[(0,16,4),(1,0,4)])
    def tearDown(self):self.tmp.cleanup()
    def run_core(self,fault=None,missing_quiescence=False):
        k=Kernel(self.root,self.before,fault);state=c.create_string_buffer(self.lib.platform_size())
        if missing_quiescence:k.services.enter=core.Fn0()
        self.lib.lp_linux_init(state,c.byref(k.services));io_ptr=self.lib.platform_io(state)
        r=core.Report();w=core.Workspace();self.lib.lp_run(c.byref(self.plan),io_ptr,c.byref(w),c.byref(r))
        self.assertEqual(k.errors,[]);self.assertFalse(k.fds);self.assertFalse(k.quiesced)
        return k,r
    def test_install_and_same_inode(self):
        k,r=self.run_core();self.assertEqual(r.outcome,1);self.assertTrue(k.ro)
        self.assertEqual([p.read_bytes() for p in k.paths],self.after)
        self.assertEqual([p.stat().st_ino for p in k.paths],k.initial_inodes)
        self.assertEqual([e[1] for e in k.events if isinstance(e,tuple) and e[0]=='remount'],[0xc30,0xc31])
    def test_missing_quiescence_never_calls_kernel(self):
        k,r=self.run_core(missing_quiescence=True);self.assertEqual((r.outcome,r.status,k.calls),(3,-95,0))
    def test_prewrite_rejections(self):
        for fault in ('not_root','lock_busy','unsafe_lock','quiesce_enter','wrong_device','wrong_fs','duplicate_usr','missing_cp','cp_ro','duplicate_mode','unknown_usr_option','truncated_mounts','oversized_mounts','mount_read_eintr_forever','leaf_symlink','dir_symlink','file_device','hardlink'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix='lut-platform-reject-') as d:
                self.root=Path(d);k,r=self.run_core(fault);self.assertEqual(r.outcome,3)
                self.assertFalse(r.writes_started);self.assertFalse(any(isinstance(e,tuple) and e[0]=='write' for e in k.events))
    def test_remount_verification_and_restore_on_failed_transition(self):
        for fault in ('remount_no_change','rw_error_after_change','changed_cp_options','changed_inode'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix='lut-platform-remount-') as d:
                self.root=Path(d);k,r=self.run_core(fault);self.assertEqual(r.outcome,3)
                self.assertFalse(r.writes_started);self.assertTrue(k.ro)
    def test_io_failures_rollback_and_cleanup_failures_unknown(self):
        for fault in ('partial_write','fsync','file_close','restore_ro_failure','quiesce_leave'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix='lut-platform-fault-') as d:
                self.root=Path(d);k,r=self.run_core(fault)
                self.assertEqual(r.outcome,2 if fault in ('partial_write','fsync') else 0)
                self.assertEqual([p.read_bytes() for p in k.paths],self.before if r.outcome==2 else self.after)
    def test_short_reads_and_bounded_interrupts(self):
        for fault in ('mount_read_eintr','mount_short_read','file_short_io','policy_flags'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix='lut-platform-short-') as d:
                self.root=Path(d);k,r=self.run_core(fault);self.assertEqual(r.outcome,1)
                self.assertEqual([p.read_bytes() for p in k.paths],self.after)

if __name__=='__main__':unittest.main(verbosity=2)
