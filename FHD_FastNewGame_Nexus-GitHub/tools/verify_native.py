#!/usr/bin/env python3
"""Execute rebuilt PE32 plugin with a real mapped EXE and mocked Windows/worker calls."""
import argparse,hashlib,json,struct
from pathlib import Path
import pefile
from functools import lru_cache
@lru_cache(maxsize=4)
def mapped(path):
    pe=pefile.PE(str(path));return pe.OPTIONAL_HEADER.ImageBase,pe.OPTIONAL_HEADER.SizeOfImage,pe.get_memory_mapped_image(),{e.name.decode():pe.OPTIONAL_HEADER.ImageBase+e.address for e in getattr(pe,'DIRECTORY_ENTRY_EXPORT',type('Empty',(),{'symbols':[]})()).symbols if e.name},pe.OPTIONAL_HEADER.ImageBase+pe.OPTIONAL_HEADER.AddressOfEntryPoint
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EIP,UC_X86_REG_EAX
EXPECTED='83300344af802bc51e64389c58f047e5afdf195c133048098be3881fae29ed98'
class Probe:
    ENV=0x2000000;KERNEL=0x50000000;STOP=0x2001000;STACK=0x21f0000
    def __init__(self,dll,exe,days=60,direct=True,protect_fail=0):
        self.u=Uc(UC_ARCH_X86,UC_MODE_32);self.events=[];self.protect_count=0;self.protect_fail=protect_fail;self.days=days;self.direct=direct;self.heap=0x2010000
        for start,size in [(0,4096),(self.ENV,0x200000),(self.KERNEL,0x10000)]:self.u.mem_map(start,size)
        _,self.game_size,payload,_,_=mapped(str(exe));self.u.mem_map(0x400000,(self.game_size+4095)&~4095);self.u.mem_write(0x400000,payload)
        self.base,plugin_size,payload,self.exports,self.entry=mapped(str(dll));self.u.mem_map(self.base,(plugin_size+4095)&~4095);self.u.mem_write(self.base,payload)
        self.put(0x30,self.ENV);self.put(self.ENV+8,0x400000);self.put(self.ENV+12,self.ENV+0x100)
        head=self.ENV+0x114;entry=self.ENV+0x200;self.put(head,entry+8);self.put(entry+8,head);self.put(entry+0x18,self.KERNEL);self.put(entry+0x30,self.wide('kernelbase.dll'))
        # Minimal valid PE export directory for the three APIs resolved by the C code.
        k=self.KERNEL;self.u.mem_write(k,b'MZ');self.put(k+0x3c,0x80);self.put(k+0x80,0x4550);self.u.mem_write(k+0x98,b'\x0b\x01');self.put(k+0x98+96,0x1000);self.put(k+0x98+100,0x400)
        for off,val in [(20,3),(24,3),(28,0x1100),(32,0x1120),(36,0x1140)]:self.put(k+0x1000+off,val)
        for i,name in enumerate(['VirtualProtect','FlushInstructionCache','GetModuleHandleExW']):
            self.put(k+0x1100+4*i,0x2000+i*0x10);self.put(k+0x1120+4*i,0x1180+i*0x30);self.u.mem_write(k+0x1140+2*i,struct.pack('<H',i));self.u.mem_write(k+0x1180+i*0x30,name.encode()+b'\0')
        self.holder=self.alloc(bytes(4));self.job=self.alloc(bytes(64));self.put(self.holder,self.job);self.put(0x88222c,self.holder)
        self.mods('FHD_MODS\\FHD_FastNewGame');self.u.mem_write(0x87a6e0,b'\0')
        self.host=self.alloc(bytes(44));self.put(self.host,44);self.put(self.host+4,1);self.put(self.host+8,0x400000);self.put(self.host+24,self.wide('test.ini'));self.put(self.host+28,self.ENV+0x2200);self.put(self.host+32,self.ENV+0x2210);self.put(self.host+36,self.ENV+0x2220)
        self.u.hook_add(UC_HOOK_CODE,self.hook)
    def put(self,a,v):self.u.mem_write(a,struct.pack('<I',v&0xffffffff))
    def get(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
    def alloc(self,b):a=self.heap;self.heap+=(len(b)+15)&~15;self.u.mem_write(a,b);return a
    def wide(self,s):return self.alloc(s.encode('utf-16-le')+b'\0\0')
    def readwide(self,a):
        if not a:return ''
        b=bytearray()
        for i in range(2000):
            c=bytes(self.u.mem_read(a+2*i,2))
            if c==b'\0\0':return b.decode('utf-16-le')
            b+=c
        raise AssertionError('Unterminated test string')
    def mods(self,s):self.put(0x888ef0,self.wide(s) if s is not None else 0)
    def ret(self,n,value=0):
        sp=self.u.reg_read(UC_X86_REG_ESP);address=self.get(sp);self.u.reg_write(UC_X86_REG_EAX,value);self.u.reg_write(UC_X86_REG_ESP,sp+4+4*n);self.u.reg_write(UC_X86_REG_EIP,address)
    def hook(self,u,pc,size,user):
        sp=u.reg_read(UC_X86_REG_ESP)
        arg=lambda n:self.get(sp+4+4*n)
        if pc==self.KERNEL+0x2000:
            self.protect_count+=1;self.events.append(('protect',arg(0),arg(1),arg(2)))
            if self.protect_count==self.protect_fail:self.ret(4,0)
            else:self.put(arg(3),0x20);self.ret(4,1)
        elif pc==self.KERNEL+0x2010:self.events.append(('flush',arg(1),arg(2)));self.ret(3,1)
        elif pc==self.KERNEL+0x2020:self.events.append(('pin',arg(0)));self.put(arg(2),self.base);self.ret(3,1)
        elif pc==self.ENV+0x2200:self.events.append(('log',self.readwide(arg(1))));self.ret(2)
        elif pc==self.ENV+0x2210:self.ret(4,int(self.direct))
        elif pc==self.ENV+0x2220:self.ret(6,self.days)
        elif pc==0x72f91c:self.events.append(('calculate',self.get(self.job+0x2c)));self.ret(0)
        elif pc in (0x4d75bc,0x4d75d0):self.events.append(('vanilla',1 if pc==0x4d75bc else 2));self.ret(0)
    def call(self,pc,*args):
        sp=self.STACK;self.u.mem_write(sp,struct.pack('<'+'I'*(len(args)+1),self.STOP,*args));self.u.reg_write(UC_X86_REG_ESP,sp);self.u.reg_write(UC_X86_REG_EAX,0);self.u.emu_start(pc,self.STOP,count=2000000);return self.u.reg_read(UC_X86_REG_EAX)
    def init(self):return self.call(self.exports['XenoPlugin_Initialize'],self.host)
    def game_hash(self):return hashlib.sha256(self.u.mem_read(0x400000,self.game_size)).hexdigest()
    def dispatch(self,site):
        before=len(self.events);self.call(site);return [e for e in self.events[before:] if e[0] in ('calculate','vanilla')]
    def hook_target(self,site):return site+5+struct.unpack('<i',self.u.mem_read(site+1,4))[0]
    def preloop(self):return self.dispatch(self.hook_target(0x5d5d66))
    def loop1(self):return self.dispatch(self.hook_target(0x5d5dbb))
    def loop2(self):return self.dispatch(self.hook_target(0x5d5d9f))

def verify(dll,exe):
    assert hashlib.sha256(Path(exe).read_bytes()).hexdigest()==EXPECTED,'Wrong game fixture'
    checks=[]
    def check(label,condition):assert condition,label;checks.append(label)
    p=Probe(dll,exe);info=p.alloc(bytes(528));p.put(info,528)
    check('DllMain accepts normal load',p.call(p.entry,p.base,1,0)==1)
    check('Query rejects null info',p.call(p.exports['XenoPlugin_Query'],0)==0)
    p.put(info,519);check('Query rejects short ABI structure',p.call(p.exports['XenoPlugin_Query'],info)==0)
    p.put(info,528);check('Query returns correct version and API',p.call(p.exports['XenoPlugin_Query'],info)==1 and p.get(info+4)==1 and p.readwide(info+8)=='FHD_FastNewGame' and p.readwide(info+136)=='0.2.3' and p.get(info+520)==0)
    check('Initialize rejects null host',p.call(p.exports['XenoPlugin_Initialize'],0)==87)
    before=p.game_hash();check('Initialize accepts original game and applies hooks',p.init()==0 and p.game_hash()!=before)
    check('Initialize logs success and pins module',('log','patch_applied') in p.events and ('pin',5) in p.events)
    check('Three callsites point into rebuilt plugin',all(p.base<=p.hook_target(s)<p.base+0xd000 for s in (0x5d5d66,0x5d5d9f,0x5d5dbb)))
    check('Active preloop sets 61 boundary and executes direct job1 stub',p.preloop()==[('calculate',1)] and p.get(0x5d5ddd)==61)
    check('Direct job2 stub dispatches original calculation entry',p.loop2()==[('calculate',2)])
    check('Direct job1 loop dispatches original calculation entry',p.loop1()==[('calculate',1)])
    p.mods('OtherMod');check('Live disable restores 301 boundary and vanilla job1',p.preloop()==[('vanilla',1)] and p.get(0x5d5ddd)==301)
    check('Disabled mode restores vanilla job2',p.loop2()==[('vanilla',2)])
    p.mods('fhd_mods\\fhd_fastnewgame');check('Live reenable recognizes lowercase token',p.preloop()==[('calculate',1)] and p.get(0x5d5ddd)==61)
    p.u.mem_write(0x87a6e0,b'\1');check('NoMods flag restores vanilla mode',p.preloop()==[('vanilla',1)] and p.get(0x5d5ddd)==301)
    p.u.mem_write(0x87a6e0,b'\0');p.mods(None);check('Null mod list is disabled safely',p.preloop()==[('vanilla',1)])
    p.mods('');check('Empty mod list is disabled safely',p.preloop()==[('vanilla',1)])
    after=p.game_hash();check('Repeated initialization is idempotent',p.init()==0 and p.game_hash()==after)
    for days in (1,60,300):
        for direct in (False,True):
            q=Probe(dll,exe,days,direct);check(f'Config {days}/{int(direct)} initializes',q.init()==0)
            check(f'Config {days}/{int(direct)} selects days and dispatch',q.preloop()==[('calculate' if direct else 'vanilla',1)] and q.get(0x5d5ddd)==days+1)
    for days in (0,301,-1):
        q=Probe(dll,exe,days);before=q.game_hash();check(f'Invalid days {days} rejected before game writes',q.init()==87 and q.game_hash()==before and q.protect_count==0)
    for field,value in ((0,31),(4,2),(8,0),(8,0x1000000)):
        q=Probe(dll,exe);q.put(q.host+field,value);before=q.game_hash();expected=50 if field==8 and value else 87;check(f'Invalid host field {field}/{value} rejected',q.init()==expected and q.game_hash()==before)
    nt=0x400000+p.get(0x40003c)
    for address in (0x400000,nt,nt+4,nt+8,nt+24,nt+40,nt+52,nt+80,0x5d5dda,0x5d5d66,0x5d5d9f,0x5d5dbb,0x874720,0x72f91c):
        q=Probe(dll,exe);old=bytes(q.u.mem_read(address,1));q.u.mem_write(address,bytes([old[0]^1]));before=q.game_hash();check(f'Altered identity/signature {address:#x} rejected',q.init()==50 and q.game_hash()==before and q.protect_count==0)
    for failure in (1,2):
        q=Probe(dll,exe,protect_fail=failure);before=q.game_hash();check(f'VirtualProtect failure {failure} aborts without game writes',q.init()==29 and q.game_hash()==before)
    q=Probe(dll,exe);check('Standalone ScriptLibs export initializes via PEB',q.call(q.exports['FHDFastNewGame_Init'])==0 and q.preloop()==[('calculate',1)])
    return {'status':'PASS','plugin_sha256':hashlib.sha256(Path(dll).read_bytes()).hexdigest(),'checks':checks,'count':len(checks),'fixture_sha256':EXPECTED,'compiled_plugin_instructions_executed':True,'actual_game_calculation_executed':False,'windows_game_process_started':False,'live_rscript_vm_executed':False,'windows_apis_mocked':True}
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--dll',type=Path,required=True);parser.add_argument('--exe',type=Path,required=True);parser.add_argument('--report',type=Path,required=True);a=parser.parse_args();r=verify(a.dll,a.exe);a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(r,indent=2)+'\n');print('PASS native plugin checks:',r['count'])
