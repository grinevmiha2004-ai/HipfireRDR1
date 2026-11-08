import sys,struct,json,unittest,importlib.util,re
from pathlib import Path
sys.path.insert(0,'/workspace/hipfire-reload/python-deps')
import pefile
from unicorn.x86_const import *
R=Path(__file__).parent
spec=importlib.util.spec_from_file_location('baseline','/workspace/hipfire-series4/test_rapid.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=pefile.PE(str(R/'output/HipfireRDR1.red'));m.s.old.PLUGIN_IMAGE=p.get_memory_mapped_image()
syms=json.loads((R/'symbols.json').read_text())
game=pefile.PE('/workspace/hipfire-reload/RDR.exe',fast_load=True)
class HandgunTests(m.s.SeriesTests):
 def vm(self,*args,**kwargs):
  v=super().vm(*args,**kwargs);v.callbacks[v.base+0xd870]=lambda:4;return v
class LongarmTests(m.GuardTests):
 def call(self,v,name,*args):
  end=0x5000f000;sp=v.frame-8;v.q(sp,end);v.u.reg_write(UC_X86_REG_RSP,sp)
  for reg,value in zip([UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9],args):v.u.reg_write(reg,value)
  v.u.emu_start(v.base+syms[name][0],end,count=1000000);self.assertEqual(v.u.reg_read(UC_X86_REG_RIP),end)
  return v.u.reg_read(UC_X86_REG_RAX)
 def fixture(self,w=9,k=0,base=0x1cf0c0000,v=None):
  v=v or self.vm(base);v.model=w;v.nodes={};v.children={};v.nodes_next=v.heap+0x40000;v.array_next=v.heap+0x60000
  v.callbacks[v.base+0xd870]=lambda:v.model
  v.native_calls=[];v.old_nodes=[];v.play_queries=[]
  def oldselect():
   text=bytes(v.u.mem_read(v.u.reg_read(UC_X86_REG_RDX),256)).split(b'\0')[0].decode();v.old_nodes.append(text);return 1
  v.callbacks[v.base+0xd730]=oldselect;v.callbacks[v.base+0xd7f0]=lambda:1;v.callbacks[v.base+0xda70]=lambda:1
  # Real native selector continuation from the user's EXE, including reference counting.
  for rva,n in [(0xcdfa20,9),(0xcdfa7a,0x8d),(0x219640,5),(0x585e60,5),(0x585e70,11)]:v.u.mem_write(v.game+rva,game.get_data(rva,n))
  v.vt=v.game+0x1cbf468;v.q(v.vt+8,v.game+0x219640);v.q(v.vt+0x58,v.game+0x585e60);v.q(v.vt+0x60,v.game+0x585e70);v.q(v.vt+0x88,v.game+0x588060)
  v.ctrl=v.heap+0x30000;v.instance=v.heap+0x31000;v.shared=v.heap+0x32000;v.q(v.owner+0xb0,v.ctrl);v.q(v.instance+0x20,v.shared)
  v.q(v.shared+0x20,1)
  def create():
   v.selected=v.u.reg_read(UC_X86_REG_RCX)
   self.assertEqual(v.u.reg_read(UC_X86_REG_RDX),v.ctrl+0x5e0)
   v.native_calls.append(('create',v.selected));return v.instance
  def schedule():
   self.assertEqual(v.u.reg_read(UC_X86_REG_RCX),v.ctrl);self.assertEqual(v.u.reg_read(UC_X86_REG_RDX),v.instance);self.assertEqual(v.u.reg_read(UC_X86_REG_R8),0)
   v.native_calls.append(('schedule',v.instance));v.q(v.ctrl+0xb0,v.selected);return 0
  def addref():
   ptr=v.u.reg_read(UC_X86_REG_RCX);v.i(ptr+0x20,v.geti(ptr+0x20)+1);v.native_calls.append(('addref',ptr));return 0xabcd0000
  v.callbacks[v.game+0x588060]=create;v.callbacks[v.game+0x588190]=create;v.callbacks[v.game+0xaddf40]=schedule;v.callbacks[v.game+0x5889e0]=addref
  v.callbacks[v.game+0x588610]=lambda:v.native_calls.append(('release',v.u.reg_read(UC_X86_REG_RCX))) or 0
  def add(name,hash,parent=0):
   addr=v.nodes_next;v.nodes_next+=0x100;v.nodes[name]=addr;v.children[addr]=[]
   v.u.mem_write(addr,struct.pack('<QQQHHIQQQII',v.vt,parent,0,0,0,0,0,0,0,hash,0))
   if parent:
    v.children[parent].append(addr);arr=v.array_next;v.array_next+=0x1000
    v.q(parent+0x10,arr);v.u.mem_write(parent+0x18,struct.pack('<HH',len(v.children[parent]),len(v.children[parent])))
    v.u.mem_write(arr,struct.pack('<'+'Q'*len(v.children[parent]),*v.children[parent]))
   return addr
  v.add=add
  globalnode=add('global',0xdb982272);v.q(v.game+0x2ab5e78,globalnode)
  base_node=add('base',0xbd701184,globalnode)
  # Standing path recovered from the user's actual native Winchester execution.
  gun=add('gun',0x18e67533,base_node);rifle=add('rifle',0x840a9c18,gun)
  de=add('standing_de',0xbcacd642,rifle);middle=add('middle',0xafd53e15,de)
  v.target=add('standing',0x61d07327,middle)
  # Normal shoulder/hold has the same leaf name but MUST NOT be selected.
  normal=add('normal',0x0139c40d,rifle);add('normal_standing',0x61d07327,normal)
  motion=add('motion',0xf6ad55f0,base_node);mr=add('motion_rifle',0x840a9c18,motion);md=add('motion_de',0x122ac9f4,mr)
  add('moving',0x7e84a609,md)
  crouchbase=add('crouchbase',0x892a3c35,base_node);crouch=add('crouch',0x2751a740,crouchbase);cd=add('crouch_de',0xbcacd642,crouch)
  add('crouched',0x61d07327,cd);add('crouched_moving',0x7e84a609,cd)
  leafvt=v.game+0x1cbf520
  v.q(leafvt+8,v.game+0x219640);v.q(leafvt+0x58,v.game+0x585e60);v.q(leafvt+0x60,v.game+0x585e70);v.q(leafvt+0x88,v.game+0x588190)
  for name in ['standing','moving','crouched','crouched_moving']:v.q(v.nodes[name],leafvt)
  v.leafvt=leafvt
  v.expected=[v.nodes[x] for x in ['standing','moving','crouched','crouched_moving']][k]
  return v
 def path(self,v,k):
  rv=[0x202c0,0x201b8,0x20200,0x20260][k];text=bytes(p.get_data(rv,256)).split(b'\0')[0]
  pointer=v.heap+0x20000;v.u.mem_write(pointer,text+b'\0');return pointer,text.decode()
 def test_winchester_uses_captured_path_and_real_selector_body(self):
  v=self.fixture();ptr,_=self.path(v,0)
  self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(v.selected,v.target);self.assertEqual(v.old_nodes,[])
  self.assertEqual(v.native_calls,[('create',v.target),('schedule',v.instance),('addref',v.shared)])
  self.assertEqual(v.getq(v.ctrl+0x5a8),v.shared);self.assertEqual(v.geti(v.shared+0x20),2)
  self.assertEqual(self.call(v,'playing_node',42,ptr),1);self.assertEqual(self.call(v,'rapid_pose',42,0,0)&255,1)
 def test_all_rifle_models_in_each_scoped_pose(self):
  for w in list(range(8,15))+list(range(16,21)):
   for k in range(4):
    v=self.fixture(w,k);ptr,_=self.path(v,k)
    self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(v.selected,v.expected)
    self.assertEqual(self.call(v,'rapid_pose',42,k&1,k>=2)&255,1)
 def test_sawedoff_and_original_handguns_keep_exact_pistol_routes(self):
  for w in list(range(8))+[15]:
   for k in range(4):
    v=self.fixture(w,k);ptr,path=self.path(v,k)
    self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(v.old_nodes,[path]);self.assertEqual(v.native_calls,[])
    self.assertEqual(self.call(v,'rapid_pose',42,k&1,k>=2)&255,1)
 def test_child_descendant_active_without_guessing_clip_names(self):
  v=self.fixture();ptr,_=self.path(v,0);self.call(v,'select_node',42,ptr)
  descendant=v.add('firechild',0x12345678,v.target);v.q(v.ctrl+0xb0,descendant)
  self.assertEqual(self.call(v,'playing_node',42,ptr),1)
  v.q(v.ctrl+0xb0,v.nodes['normal_standing']);self.assertEqual(self.call(v,'playing_node',42,ptr),0)
 def test_missing_crouch_and_ambiguous_tree_refuse_without_standing_fallback(self):
  for issue in ['missing','ambiguous']:
   v=self.fixture();k=2 if issue=='missing' else 0;ptr,_=self.path(v,k)
   if issue=='missing':v.i(v.nodes['crouched']+0x38,0x1234)
   else:v.add('duplicate',0x61d07327,v.nodes['middle'])
   self.assertEqual(self.call(v,'select_node',42,ptr),0);self.assertEqual(v.native_calls,[]);self.assertEqual(v.old_nodes,[])
 def test_tampered_engine_code_layout_tree_and_nonlocal_actor_refuse(self):
  for issue in ['code','prologue','layout','global','owner','create']:
   v=self.fixture();ptr,_=self.path(v,0)
   if issue=='prologue':v.u.mem_write(v.game+0xcdfa20,b'\x90')
   if issue=='code':v.u.mem_write(v.game+0xcdfa7a,b'\x90')
   if issue=='layout':v.q(v.vt+0x58,v.game+0x585e61)
   if issue=='global':v.q(v.game+0x2ab5e78,0)
   if issue=='owner':v.i(v.controller+0x5ec,99)
   if issue=='create':v.q(v.leafvt+0x88,0x50001000) # outside game code range
   self.assertEqual(self.call(v,'select_node',42,ptr),0);self.assertEqual(v.native_calls,[])
 def test_unknown_weapon_transient_and_weapon_change_invalidate_cache(self):
  v=self.fixture();ptr,_=self.path(v,0);self.call(v,'select_node',42,ptr)
  v.model=-1;self.assertEqual(self.call(v,'playing_node',42,ptr),1)
  v.model=13;self.assertEqual(self.call(v,'playing_node',42,ptr),0)
 def test_native_selector_preserves_reference_count_and_nonvolatile_registers(self):
  v=self.fixture();ptr,_=self.path(v,0);oldref=v.heap+0x35000;v.q(v.ctrl+0x5a8,oldref);v.i(oldref+0x20,1)
  regs=[UC_X86_REG_RBX,UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_RBP,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15]
  for i,reg in enumerate(regs):v.u.reg_write(reg,0x123456780000+i)
  before=[v.u.reg_read(r) for r in regs]
  self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(before,[v.u.reg_read(r) for r in regs])
  self.assertIn(('release',oldref),v.native_calls);self.assertEqual(v.geti(oldref+0x20),0)
 def test_relocated_tree_resolver(self):
  for base in [0x180000000,0x7ff800000000]:
   v=self.fixture(base=base);ptr,_=self.path(v,0);self.assertEqual(self.call(v,'select_node',42,ptr),1)
 def test_weapon_gate_keeps_nonfirearms_excluded(self):
  for w in range(-2,39):
   v=self.vm();v.i(v.frame+0x6c,w);v.run(0x4047,0x4052 if 0<=w<=20 else 0x4812)
 def test_original_release_root_and_native_create_failure(self):
  v=self.fixture();ptr=v.heap+0x20000;v.u.mem_write(ptr,b'default_character_Main\0')
  self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(v.old_nodes,['default_character_Main'])
  v=self.fixture();ptr,_=self.path(v,0);v.callbacks[v.game+0x588190]=lambda:0
  self.assertEqual(self.call(v,'select_node',42,ptr),1) # matches the original native's own success semantics
  self.assertEqual(v.getq(v.ctrl+0x5a8),0);self.assertEqual(self.call(v,'playing_node',42,ptr),0)
 def test_real_start_branch_for_each_longarm_and_pose(self):
  for w in [8,9,12,15,16,17,18,19,20]:
   for k in range(4):
    v=HandgunTests().vm(kind=k);self.fixture(w,k,v=v)
    # Keep the original test's node-call record for sawed-off passthrough.
    v.run(0x5c94,0x5b3f)
    self.assertEqual(v.geti(v.base+0xf7cc),42);self.assertEqual(v.geti(v.base+0x24080),k)
    self.assertIn('aim',[c[0] for c in v.calls])
 def test_transitions_between_four_poses_retain_correct_active_node(self):
  v=self.fixture()
  for k in [0,1,3,2,1,0]:
   ptr,_=self.path(v,k);self.assertEqual(self.call(v,'select_node',42,ptr),1)
   self.assertEqual(v.selected,v.nodes[['standing','moving','crouched','crouched_moving'][k]])
   self.assertEqual(self.call(v,'rapid_pose',42,k&1,k>=2)&255,1)
  self.assertEqual(v.geti(v.shared+0x20),2)
 def test_real_autoreload_request_with_new_weapon_bookkeeping(self):
  for w in range(8,21):
   v=self.vm();v.i(v.base+0xf7cc,-1);v.f(v.frame+0x828,0)
   v.i(v.frame+0x6c,w);v.i(v.frame+0x76c,w);v.real_engine()
   v.mark();v.tick();self.assertEqual(v.requests,1);self.assertEqual(v.pending(),-1)
   self.assertEqual(v.u.mem_read(v.weapon+0x5d4,1)[0]&0x40,0x40)
 def test_final_pe_and_original_sections(self):
  original=pefile.PE('/workspace/hipfire-series4/output/HipfireRDR1.red');allowed=set()
  for patch in json.loads((R/'patch-report.json').read_text()):
   off=original.get_offset_from_rva(int(patch['rva'],16));allowed.update(range(off,off+len(bytes.fromhex(patch['before']))))
  for a,b in zip(original.sections,p.sections):
   x=a.get_data();y=b.get_data();self.assertEqual(len(x),len(y));self.assertTrue(all(a.PointerToRawData+j in allowed for j,(u,v) in enumerate(zip(x,y)) if u!=v),a.Name)
  end=0x1000
  for section in p.sections:
   self.assertEqual(section.VirtualAddress,end);end=(end+max(section.Misc_VirtualSize,section.SizeOfRawData)+4095)//4096*4096
  self.assertEqual(end,p.OPTIONAL_HEADER.SizeOfImage);self.assertTrue(p.verify_checksum());self.assertFalse(p.get_warnings())
  entries={e.struct.BeginAddress:e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION}
  self.assertIn(syms['select_resolved'][0],entries)
suite=unittest.TestSuite()
for cls,excluded in [(m.s.old.Tests,{'test_original_sections_preserved'}),(HandgunTests,{'test_binary_scope_and_pe_layout'}),(LongarmTests,set())]:
 for name in unittest.defaultTestLoader.getTestCaseNames(cls):
  if name not in excluded:suite.addTest(cls(name))
r=unittest.TextTestRunner(verbosity=2).run(suite);sys.exit(not r.wasSuccessful())
