import sys,struct,subprocess,unittest,random
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent/'python-deps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UcError
from unicorn.x86_const import *
ROOT=Path(__file__).parent
GAME_PE=pefile.PE(str(ROOT/'friend-RDR.exe'))
GAME_CODE=GAME_PE.get_data(0xd1dde0,0x460)
PLUGIN_IMAGE=pefile.PE(str(ROOT/'output/HipfireRDR1.red')).get_memory_mapped_image()
SYMS={line.split()[2]:int(line.split()[0],16) for line in subprocess.check_output(['nm','-n','/workspace/hipfire-reload/extension.elf'],text=True).splitlines() if len(line.split())==3}
class VM:
 def __init__(self,base=0x1cf0c0000):
  self.base=base;self.game=0x140000000;self.stack=0x10000000;self.frame=self.stack+0x10000;self.heap=0x70000000
  self.u=Uc(UC_ARCH_X86,UC_MODE_64);self.u.mem_map(base,0x70000);self.u.mem_map(self.stack,0x20000);self.u.mem_map(self.heap,0x100000);self.u.mem_map(0x50000000,0x10000);self.u.mem_map(self.game,0x3000000)
  self.u.mem_write(base,PLUGIN_IMAGE)
  self.callbacks={};self.requests=0;self.logs=0;self.reserve=True;self.ctx=0;self.ok=True;self.hash=0
  self.owner=self.heap+0x1000;self.character=self.heap+0x2000;self.manager=self.heap+0x4000;self.weapon=self.heap+0x5000;self.controller=self.heap+0x7000;self.inventory=self.heap+0x8000;self.item=self.heap+0x9000
  self.q(base+0xf8f0,self.game);self.b(base+0xf7c8,1);self.b(base+0xf960,1);self.i(base+0xf7cc,-1)
  self.q(base+0x362d8,0x50000000);self.q(base+0x24030,0x50000100);self.q(base+0x24020,0x50000200)
  self.q(self.game+0x22daf30,self.controller);self.i(self.owner+8,42);self.i(self.controller+0x5ec,42)
  self.q(self.owner+0x38,self.character);self.q(self.owner+0x70,self.inventory);self.b(self.owner+0x118,3);self.q(self.character+0x10,self.owner);self.q(self.character+0xaa8,self.manager);self.q(self.manager+8,self.weapon);self.q(self.weapon+8,self.character);self.b(self.weapon+0x5d6,0x40);self.i(self.weapon+0x3bc,8);self.f(self.weapon+0x24,-1)
  self.q(self.inventory+0x80,self.item);self.q(self.item,self.heap+0xa000)
  for o in [0x20,0x28,0x38]: self.q(self.manager+o,self.heap+0xb000+o*16)
  self.u.mem_write(self.game+0xd1dde0,GAME_CODE)
  self.callbacks={base+0x20f0:self.supported,base+0x2150:self.context,base+0x1ac0:self.actor_from,base+0x1c90:self.log,0x50000000:self.rpm,0x50000100:self.init,0x50000200:self.native,self.game+0xd1dde0:self.request}
  self.u.hook_add(UC_HOOK_CODE,self.hook)
  self.reset_frame()
 def real_engine(self,reserve=12):
  self.real=True
  self.callbacks.pop(self.game+0xd1dde0)
  self.callbacks[0x50000300]=lambda:self.heap+0xc100
  self.callbacks[self.game+0x208000]=lambda:0
  self.q(self.heap+0xa000+0xd8,0x50000300)
  self.q(self.heap+0xc100+0xa0,self.heap+0xd000)
  self.q(self.heap+0xd000+0x28,self.heap+0xe000)
  self.q(self.heap+0xe000+0x30,self.heap+0xf000)
  self.f(self.heap+0xf000+0xc4,6)
  self.f(self.heap+0xf000+0xcc,reserve)
  self.f(self.game+0x1d70b68,1)
  self.q(self.game+0x2c45770,self.heap+0xf400)
  self.u.mem_write(self.game+0x301240,GAME_PE.get_data(0x301240,0x28))
 def reset_frame(self):
  self.q(self.frame+0x40,1000);self.i(self.frame+0x68,42);self.i(self.frame+0x6c,4);self.i(self.frame+0x768,42);self.i(self.frame+0x76c,4);self.f(self.frame+0x828,0);self.q(self.frame+0x760,0);self.b(self.frame+0x770,0)
 def q(self,a,v):self.u.mem_write(a,struct.pack('<Q',v&0xffffffffffffffff))
 def i(self,a,v):self.u.mem_write(a,struct.pack('<I',v&0xffffffff))
 def b(self,a,v):self.u.mem_write(a,bytes([v]))
 def f(self,a,v):self.u.mem_write(a,struct.pack('<f',v))
 def getq(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
 def geti(self,a):return struct.unpack('<i',self.u.mem_read(a,4))[0]
 def hook(self,u,a,size,data):
  if a==self.game+0xd1dde0 and getattr(self,'real',False):self.requests+=1
  if a in self.callbacks:
   result=self.callbacks[a]()
   if result is not None:u.reg_write(UC_X86_REG_RAX,result)
   rsp=u.reg_read(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RIP,self.getq(rsp));u.reg_write(UC_X86_REG_RSP,rsp+8)
 def supported(self):return int(self.ok)
 def context(self):return self.ctx
 def actor_from(self):return self.owner
 def log(self):self.logs+=1;return 0
 def rpm(self):
  u=self.u;src=u.reg_read(UC_X86_REG_RDX);dst=u.reg_read(UC_X86_REG_R8);n=u.reg_read(UC_X86_REG_R9);got=self.getq(u.reg_read(UC_X86_REG_RSP)+40)
  try: self.u.mem_write(dst,bytes(self.u.mem_read(src,n)));self.q(got,n);return 1
  except UcError:self.q(got,0);return 0
 def init(self):self.hash=self.u.reg_read(UC_X86_REG_RCX);return 0
 def native(self):self.q(self.heap+0xc000,0);return self.heap+0xc000
 def request(self):
  assert self.u.reg_read(UC_X86_REG_RCX)==self.weapon
  self.requests+=1
  if self.reserve:self.b(self.weapon+0x5d4,0x40)
  return 0
 def run(self,rva,end):
  self.u.reg_write(UC_X86_REG_RSP,self.frame);self.u.emu_start(self.base+rva,self.base+end,count=30000)
  assert self.u.reg_read(UC_X86_REG_RIP)==self.base+end
 def mark(self,ammo=0):
  self.u.reg_write(UC_X86_REG_XMM6,struct.unpack('<I',struct.pack('<f',ammo))[0]);self.run(0x4d18,0x4d20)
 def tick(self,now=1100):self.q(self.frame+0x40,now);self.run(0x39b4,0x39bc)
 def pending(self):return self.geti(self.base+SYMS['pending'])
class Tests(unittest.TestCase):
 def test_actual_engine_request_with_reserve(self):
  v=VM();v.real_engine();v.mark();v.tick()
  self.assertEqual(v.requests,1);self.assertEqual(v.pending(),-1)
  self.assertEqual(v.u.mem_read(v.weapon+0x5d4,1)[0]&0x40,0x40)
  self.assertEqual(struct.unpack('<f',v.u.mem_read(v.heap+0xd000+0x12c,4))[0],0)
  self.assertEqual(struct.unpack('<f',v.u.mem_read(v.heap+0xf000+0xcc,4))[0],12)
  v.tick(1300);self.assertEqual(v.requests,1)
 def test_actual_engine_no_reserve_refuses(self):
  v=VM();v.real_engine(0);v.mark();before=bytes(v.u.mem_read(v.weapon,0x600));v.tick()
  self.assertEqual(v.requests,1);self.assertEqual(v.pending(),42)
  self.assertEqual(bytes(v.u.mem_read(v.weapon,0x600)),before)
 def test_unwind_entries_registered(self):
  p=pefile.PE(str(ROOT/'output/HipfireRDR1.red'))
  entries={e.struct.BeginAddress:e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION}
  for name in ['_ZL4readyPvy','_ZL3ptry','mark_empty','reload_tick','confirmed_bridge','tick_bridge']:
   e=entries[SYMS[name]];header=p.get_data(e.UnwindData,4)
   self.assertEqual(header[0]&7,1)
   if name.endswith('_bridge'):self.assertEqual(header[0]>>3,4)
 def test_windows_section_layout(self):
  p=pefile.PE(str(ROOT/'output/HipfireRDR1.red'))
  align=p.OPTIONAL_HEADER.SectionAlignment
  end=(p.OPTIONAL_HEADER.SizeOfHeaders+align-1)//align*align
  for section in p.sections:
   self.assertEqual(section.VirtualAddress,end,section.Name)
   end=(section.VirtualAddress+max(section.Misc_VirtualSize,section.SizeOfRawData)+align-1)//align*align
   if section.SizeOfRawData:
    self.assertLessEqual(section.PointerToRawData+section.SizeOfRawData,len(p.__data__))
  self.assertEqual(end,p.OPTIONAL_HEADER.SizeOfImage)
  self.assertTrue(p.verify_checksum())
 def test_last_round(self):
  v=VM();v.mark();self.assertEqual(v.pending(),42);v.tick();self.assertEqual(v.requests,1);self.assertEqual(v.logs,1);self.assertEqual(v.pending(),-1);v.tick(1300);self.assertEqual(v.requests,1)
 def test_other_confirmed_ammo(self):
  for ammo in [1,6,9,15,float('nan'),float('inf'),-1]:
   with self.subTest(ammo=ammo):v=VM();v.mark(ammo);v.tick();self.assertEqual(v.requests,0)
 def test_no_hipfire_confirmation(self):
  v=VM();v.tick();self.assertEqual(v.requests,0)
 def test_wait_for_release_and_cycle(self):
  v=VM();v.mark();v.i(v.base+0xf7cc,42);v.tick();self.assertEqual(v.requests,0);v.i(v.base+0xf7cc,-1);v.f(v.weapon+0x24,.1);v.tick(1200);self.assertEqual(v.requests,0);v.f(v.weapon+0x24,-1);v.tick(1400);self.assertEqual(v.requests,1)
 def test_cancelled_contexts(self):
  changes=[lambda v:v.b(v.base+0xf960,0),lambda v:v.b(v.base+0xf7c8,0),lambda v:v.i(v.frame+0x768,-1),lambda v:v.i(v.frame+0x76c,5),lambda v:v.f(v.frame+0x828,6),lambda v:setattr(v,'ctx',32),lambda v:setattr(v,'ctx',2),lambda v:setattr(v,'ok',False),lambda v:v.i(v.controller+0x5ec,99),lambda v:v.q(v.character+0x10,0),lambda v:v.q(v.weapon+8,0),lambda v:v.b(v.owner+0x118,1),lambda v:v.b(v.weapon+0x5d6,0),lambda v:v.i(v.weapon+0x3bc,14),lambda v:v.u.mem_write(v.game+0xd1dde0,b'\x90')]
  for idx,change in enumerate(changes):
   with self.subTest(idx=idx):v=VM();v.mark();change(v);v.tick();self.assertEqual(v.requests,0);self.assertEqual(v.pending(),-1)
 def test_pending_and_queue(self):
  for off in [0x770,0x760]:
   v=VM();v.mark();v.b(v.frame+off,1);v.tick();self.assertEqual(v.requests,0)
 def test_no_reserve_bounded(self):
  v=VM();v.reserve=False;v.mark();v.tick();v.tick(1150);self.assertEqual(v.requests,1);v.tick(1200);self.assertEqual(v.requests,2);v.tick(3501);self.assertEqual(v.pending(),-1);self.assertEqual(v.requests,2)
 def test_known_weapon_states(self):
  for state in [6,8,9,12]:
   v=VM();v.mark();v.i(v.weapon+0x3bc,state);v.tick();self.assertEqual(v.requests,1)
 def test_relocated_bridges_preserve_registers(self):
  regs=[UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RBP,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15]
  for base in [0x1cf0c0000,0x180000000,0x7ff800000000]:
   v=VM(base);v.mark()
   for n,r in enumerate(regs):v.u.reg_write(r,0x123456780000+n)
   for n in range(16):v.u.reg_write(UC_X86_REG_XMM0+n,(1<<100)+n)
   before=[v.u.reg_read(r) for r in regs];xmm=[v.u.reg_read(UC_X86_REG_XMM0+n) for n in range(16)]
   v.tick();self.assertEqual(before,[v.u.reg_read(r) for r in regs]);self.assertEqual(xmm,[v.u.reg_read(UC_X86_REG_XMM0+n) for n in range(16)]);self.assertEqual(v.requests,1)
 def test_original_sections_preserved(self):
  src=next(Path('/workspace/attachments/6274170f-4041-49a2-a8e5-58cce5a9c766').glob('*.red'));a=pefile.PE(str(src));b=pefile.PE(str(ROOT/'output/HipfireRDR1.red'))
  self.assertEqual(a.OPTIONAL_HEADER.AddressOfEntryPoint,b.OPTIONAL_HEADER.AddressOfEntryPoint)
  for sa,sb in zip(a.sections,b.sections):
   da=bytearray(sa.get_data());db=bytearray(sb.get_data())
   if sa.Name.rstrip(b'\0')==b'.text':
    for rva in [0x39b4,0x4d18]:
     off=rva-sa.VirtualAddress;db[off:off+8]=da[off:off+8]
   self.assertEqual(da,db,sa.Name)
if __name__=='__main__':unittest.main(verbosity=2)
