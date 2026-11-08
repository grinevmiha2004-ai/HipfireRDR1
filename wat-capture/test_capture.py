import sys,struct,json,unittest,importlib.util
from pathlib import Path
sys.path.insert(0,'/workspace/hipfire-reload/python-deps')
import pefile
from unicorn.x86_const import *
R=Path(__file__).parent
spec=importlib.util.spec_from_file_location('baseline','/workspace/hipfire-series4/test_rapid.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=pefile.PE(str(R/'output/HipfireRDR1.red'));m.s.old.PLUGIN_IMAGE=p.get_memory_mapped_image()
orig=m.s.old.VM.__init__
def init(self,*args,**kwargs):
 orig(self,*args,**kwargs);self.callbacks[0x50000800]=lambda:0;self.q(self.base+0x36418,0x50000800)
 # Some baseline reload tests do not install a time API stub.
 self.callbacks[0x50000900]=lambda:self.getq(self.frame+0x40);self.q(self.base+0x362a8,0x50000900)
m.s.old.VM.__init__=init
syms=json.loads((R/'symbols.json').read_text())
class CaptureTests(m.GuardTests):
 def call(self,v,name,*args):
  end=0x5000f000;sp=v.frame-8;v.q(sp,end);v.u.reg_write(UC_X86_REG_RSP,sp)
  for reg,value in zip([UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9],args):v.u.reg_write(reg,value)
  v.u.emu_start(v.base+syms[name][0],end,count=100000);self.assertEqual(v.u.reg_read(UC_X86_REG_RIP),end)
  return v.u.reg_read(UC_X86_REG_RAX)
 def setup_capture(self,base=0x1cf0c0000):
  v=self.vm(base);v.keys=set();v.events=[];v.clock=1000
  v.callbacks[0x50000800]=lambda:0x8000 if v.u.reg_read(UC_X86_REG_RCX) in v.keys else 0
  def log():
   ptr=v.u.reg_read(UC_X86_REG_RCX);fmt=bytes(v.u.mem_read(ptr,300)).split(b'\0')[0].decode()
   args=[v.u.reg_read(reg) for reg in [UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]]
   args += [v.getq(v.u.reg_read(UC_X86_REG_RSP)+40+j*8) for j in range(10)]
   v.events.append((fmt,args));return 0
  v.callbacks[v.base+0x1c90]=log
  pool=v.heap+0x30000;ctrl=v.heap+0x31000;leaf=v.heap+0x32000;root=v.heap+0x33000
  v.q(v.game+0x2c36768,pool);v.q(pool+42*16,v.owner);v.u.mem_write(pool+42*16+8,b'\0\0')
  v.q(v.owner+0xb0,ctrl);v.q(ctrl+0xb0,leaf)
  vt=v.game+0x1c00000;getter=v.game+0x100000
  v.q(leaf,vt);v.q(leaf+8,root);v.i(leaf+0x18,0x11223344)
  v.q(root,vt);v.q(root+8,0);v.i(root+0x18,0xaabbccdd)
  v.q(vt+8,getter);v.u.mem_write(getter,bytes.fromhex('488d4110c3')+b'\x90'*11)
  de=v.heap+0x34000;v.q(v.controller+0x410,de);v.i(de+0x1c,2);v.i(de+0x20,1)
  v.callbacks[0x50000a00]=lambda:0;v.q(v.base+0x24028,0x50000a00)
  def native():
   value={0xad68a22e:0,0xe8cfdd53:42,0xa4b2016d:13}[v.hash]
   v.q(v.heap+0xc000,value);return v.heap+0xc000
  v.callbacks[0x50000200]=native
  v.leaf=leaf;v.root=root;v.ctrl=ctrl;v.de=de;return v
 def tick_capture(self,v):self.call(v,'capture_tick',v.frame)
 def test_without_f9_capture_does_not_sample_or_call_natives(self):
  v=self.setup_capture();before=v.hash;self.tick_capture(v);self.assertEqual(v.events,[]);self.assertEqual(v.hash,before)
 def test_deadeye_node_parent_hash_chain_collected_readonly(self):
  v=self.setup_capture();before=bytes(v.u.mem_read(v.heap,0x40000));v.keys={0x78};self.tick_capture(v)
  self.assertEqual(bytes(v.u.mem_read(v.heap,0x40000))[:0xc000],before[:0xc000])
  # Native return buffer is a mock outside the sampled game objects.
  self.assertEqual(bytes(v.u.mem_read(v.heap+0x30000,0x5000)),before[0x30000:0x35000])
  nodes=[args for fmt,args in v.events if fmt.startswith('wat_node')]
  self.assertEqual(len(nodes),2);self.assertEqual(nodes[0][0:3],[0,v.leaf,v.root])
  self.assertEqual(nodes[0][6],0x11223344);self.assertEqual(nodes[1][6],0xaabbccdd)
  samples=[args for fmt,args in v.events if fmt.startswith('wat_capture sample')]
  self.assertEqual(samples[0][:4],[42,13,2,1])
 def test_f9_hold_deduplicates_and_f11_stops(self):
  v=self.setup_capture();v.keys={0x78};self.tick_capture(v);n=len(v.events)
  v.clock=1100;self.tick_capture(v);self.assertEqual(len(v.events),n)
  v.keys={0x7a};v.clock=1200;self.tick_capture(v);self.assertEqual(v.events[-1][0],'wat_capture stopped')
  v.q(v.ctrl+0xb0,v.root);v.keys=set();v.clock=1300;n=len(v.events);self.tick_capture(v);self.assertEqual(len(v.events),n)
 def test_timer_bounds_and_de_exec_change(self):
  v=self.setup_capture();v.keys={0x78};self.tick_capture(v);v.keys=set();v.clock=1100;v.i(v.de+0x20,0);self.tick_capture(v)
  self.assertEqual(len([fmt for fmt,args in v.events if fmt.startswith('wat_capture sample')]),2)
  v.clock=61000;self.tick_capture(v);self.assertEqual(v.events[-1][0],'wat_capture timeout')
 def test_cycle_invalid_vtable_and_missing_player_are_bounded(self):
  for mode in ['cycle','vtable','player']:
   v=self.setup_capture();v.keys={0x78}
   if mode=='cycle':v.q(v.root+8,v.leaf)
   if mode=='vtable':v.q(v.leaf,0)
   if mode=='player':v.q(v.game+0x22cbf00,0)
   self.tick_capture(v);self.assertLess(len(v.events),20)
 def test_accessor_decoding_never_executes_the_getter(self):
  v=self.setup_capture();node=v.leaf;getter=v.game+0x100000
  for code,offset in [('488d4110c3',0x10),('488d8180000000c3',0x80),('488bc1c3',0),('48c70100000000c3',None)]:
   v.u.mem_write(getter,bytes.fromhex(code)+b'\x90'*16)
   self.assertEqual(self.call(v,'decode_name',node,getter),node+offset if offset is not None else 0)
  self.assertEqual(self.call(v,'decode_name',node,0),0)
 def test_capture_works_at_relocated_module_addresses(self):
  for base in [0x180000000,0x7ff800000000]:
   v=self.setup_capture(base);v.keys={0x78};self.tick_capture(v)
   self.assertEqual(len([f for f,a in v.events if f.startswith('wat_node')]),2)
 def test_final_pe_and_original_sections(self):
  before=pefile.PE('/workspace/hipfire-series4/output/HipfireRDR1.red')
  for a,b in zip(before.sections,p.sections):
   x=a.get_data();y=bytearray(b.get_data())
   if a.VirtualAddress==0x1000:o=0x39b4-a.VirtualAddress;y[o:o+5]=x[o:o+5]
   self.assertEqual(x,y,a.Name)
  end=0x1000
  for section in p.sections:
   self.assertEqual(section.VirtualAddress,end);end=(end+max(section.Misc_VirtualSize,section.SizeOfRawData)+4095)//4096*4096
  self.assertEqual(end,p.OPTIONAL_HEADER.SizeOfImage);self.assertTrue(p.verify_checksum());self.assertFalse(p.get_warnings())
  entries={e.struct.BeginAddress:e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION}
  bridge=entries[syms['capture_bridge'][0]];self.assertEqual(p.get_data(bridge.UnwindData,1)[0],0x21)
  for name,(start,size) in syms.items():
   if 0x68000<=start<0x6a000:self.assertEqual(entries[start].EndAddress,start+size)
suite=unittest.TestSuite()
for cls,excluded in [(m.s.old.Tests,{'test_original_sections_preserved'}),(m.s.SeriesTests,{'test_binary_scope_and_pe_layout'}),(CaptureTests,set())]:
 for name in unittest.defaultTestLoader.getTestCaseNames(cls):
  if name not in excluded:suite.addTest(cls(name))
r=unittest.TextTestRunner(verbosity=2).run(suite);sys.exit(not r.wasSuccessful())
