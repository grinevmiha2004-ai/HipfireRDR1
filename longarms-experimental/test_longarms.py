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
  v=v or self.vm(base);v.model=w;v.pose=k;v.real_cover=0;v.nodes={};v.children={};v.nodes_next=v.heap+0x40000;v.array_next=v.heap+0x60000
  v.callbacks[v.base+0xd870]=lambda:v.model;v.callbacks[v.base+0x1490]=lambda:v.pose;v.callbacks[v.base+0xd8f0]=lambda:v.real_cover
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
  v.q(v.game+0x2ab5e78,base_node) # Actual native namespace: already the character root.
  # Standing path recovered from the user's actual native Winchester execution.
  gun=add('gun',0x18e67533,base_node);rifle=add('rifle',0x840a9c18,gun)
  de=add('standing_de',0xbcacd642,rifle);middle=add('middle',0xafd53e15,de)
  v.target=add('standing',0x61d07327,middle)
  add('rapid_walk',0x56bc16f8,middle);add('rapid_run',0x7e84a609,middle)
  # Normal shoulder/hold has the same leaf name but MUST NOT be selected.
  normal=add('normal',0x0139c40d,rifle);add('normal_standing',0x61d07327,normal)
  motion=add('motion',0xf6ad55f0,base_node);mr=add('motion_rifle',0x840a9c18,motion);md=add('motion_de',0x122ac9f4,mr)
  add('moving',0x7e84a609,md)
  crouchbase=add('crouchbase',0x892a3c35,base_node);crouch=add('crouch',0x2751a740,crouchbase);cd=add('crouch_de',0xbcacd642,crouch)
  cbody=add('crouch_body',0x92133daf,crouch);cr=add('crouch_rifle',0xbe49465c,cbody)
  ch=add('crouch_hold',0x0139c40d,cr);cf=add('crouch_family',0xafd53e15,ch)
  add('crouch_common',0x190080c6,ch)
  add('ordinary_crouch_stand',0x61d07327,cf);add('ordinary_crouch_walk',0x7d2d38e8,cf);add('ordinary_crouch_run',0x7e84a609,cf)
  add('crouched',0x61d07327,cd);add('crouched_moving',0x7e84a609,cd)
  leafvt=v.game+0x1cbf520
  v.q(leafvt+8,v.game+0x219640);v.q(leafvt+0x58,v.game+0x585e60);v.q(leafvt+0x60,v.game+0x585e70);v.q(leafvt+0x88,v.game+0x588190)
  for name in ['standing','rapid_walk','rapid_run','moving','crouched','crouched_moving','ordinary_crouch_stand','ordinary_crouch_walk','ordinary_crouch_run']:v.q(v.nodes[name],leafvt)
  v.leafvt=leafvt
  v.expected=v.nodes['standing'] if k==0 else v.nodes['middle'] if k==1 else v.nodes['crouch_hold']
  def live_plan():
   dst=v.u.reg_read(UC_X86_REG_RDX)
   raw=getattr(v,'live_plan',bytes(v.u.mem_read(v.base+0x24070,12))+bytes(v.u.mem_read(v.base+0x24058,4))+b'\0'*8)
   v.u.mem_write(dst,raw);return int(not getattr(v,'bad_plan',False))
  v.callbacks[v.base+0x2230]=live_plan
  v.native_args=[]
  v.q(v.base+0x24028,0x50000600)
  v.callbacks[0x50000600]=lambda:v.native_args.append(v.u.reg_read(UC_X86_REG_RCX)) or 0
  previous_native=v.callbacks[0x50000200]
  def native_camera():
   if v.hash==0x6b7677bf:v.q(v.heap+0xc000,1);return v.heap+0xc000
   if v.hash==0x4a65f0b7:
    v.u.mem_write(v.native_args[-1],struct.pack('<fff',0,0,0));return v.heap+0xc000
   return previous_native()
  v.callbacks[0x50000200]=native_camera
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
 def test_rifle_crouch_selects_ordinary_branch_instead_of_unrelated_deadeye(self):
  for k in [2,3]:
   v=self.fixture(k=k);ptr,_=self.path(v,k)
   self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(v.selected,v.expected)
   self.assertNotIn(v.selected,[v.nodes['crouched'],v.nodes['crouched_moving']])
   self.assertEqual(self.call(v,'rapid_pose',42,k&1,1)&255,1)
 def test_tampered_engine_code_layout_tree_and_nonlocal_actor_refuse(self):
  for issue in ['code','prologue','layout','global','owner','create']:
   v=self.fixture();ptr,_=self.path(v,0)
   if issue=='prologue':v.u.mem_write(v.game+0xcdfa20,b'\x90')
   if issue=='code':v.u.mem_write(v.game+0xcdfa7a,b'\x90')
   if issue=='layout':v.q(v.vt+0x58,v.game+0x585e61)
   if issue=='global':v.q(v.game+0x2ab5e78,0);v.q(v.ctrl+0xb0,0)
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
  for k in [0,1,1,0]:
   ptr,_=self.path(v,k);self.assertEqual(self.call(v,'select_node',42,ptr),1)
   self.assertEqual(v.selected,v.nodes['standing' if k==0 else 'middle'])
   self.assertEqual(self.call(v,'rapid_pose',42,k&1,k>=2)&255,1)
   v.i(v.base+0xf7cc,42);v.i(v.base+0x24080,k);v.b(v.base+0x2407e,1)
  self.assertEqual(v.geti(v.shared+0x20),2)
 def test_locomotion_family_accepts_authored_children_without_reentering(self):
  v=self.fixture(k=1);ptr,_=self.path(v,1)
  self.assertEqual(self.call(v,'select_node',42,ptr),1)
  self.assertEqual(v.selected,v.nodes['middle'])
  for name in ['rapid_walk','rapid_run','standing']:
   v.q(v.ctrl+0xb0,v.nodes[name]);self.assertEqual(self.call(v,'rapid_pose',42,1,0)&255,1)
   v.i(v.base+0xf7cc,42);v.i(v.base+0x24080,1);v.b(v.base+0x2407e,1)
   before=len(v.native_calls);self.assertEqual(self.call(v,'select_node',42,ptr),1)
   self.assertEqual(len(v.native_calls),before)
 def test_real_composite_selector_evaluates_stand_walk_run_conditions(self):
  for wanted in ['standing','rapid_walk','rapid_run',None]:
   v=self.fixture(k=1);v.u.mem_write(v.game+0x588060,game.get_data(0x588060,0x129))
   del v.callbacks[v.game+0x588060]
   for name in ['standing','rapid_walk','rapid_run']:v.b(v.nodes[name]+0x2f,4)
   v.u.mem_write(v.nodes['middle']+0x48,struct.pack('<H',0))
   def condition():
    candidate=v.u.reg_read(UC_X86_REG_RCX)-0x40
    return int(wanted is not None and candidate==v.nodes[wanted])
   v.callbacks[v.game+0x594360]=condition
   end=0x5000f000;v.q(v.frame-8,end);v.u.reg_write(UC_X86_REG_RSP,v.frame-8)
   v.u.reg_write(UC_X86_REG_RCX,v.nodes['middle']);v.u.reg_write(UC_X86_REG_RDX,v.ctrl+0x5e0)
   v.u.emu_start(v.game+0x588060,end,count=10000)
   self.assertEqual(v.u.reg_read(UC_X86_REG_RAX),v.nodes[wanted] if wanted else 0)
 def test_incomplete_locomotion_family_is_refused(self):
  for name in ['standing','rapid_walk','rapid_run']:
   v=self.fixture(k=1);v.i(v.nodes[name]+0x38,0x1234);ptr,_=self.path(v,1)
   self.assertEqual(self.call(v,'select_node',42,ptr),0);self.assertEqual(v.native_calls,[])
 def test_real_autoreload_request_with_new_weapon_bookkeeping(self):
  for w in range(8,21):
   v=self.vm();v.i(v.base+0xf7cc,-1);v.f(v.frame+0x828,0)
   v.i(v.frame+0x6c,w);v.i(v.frame+0x76c,w);v.real_engine()
   v.mark();v.tick();self.assertEqual(v.requests,1);self.assertEqual(v.pending(),-1)
   self.assertEqual(v.u.mem_read(v.weapon+0x5d4,1)[0]&0x40,0x40)
 def test_native_lookup_confirms_namespace_skips_initial_component(self):
  v=self.fixture();rva=0x5874c0;v.u.mem_write(v.game+rva,game.get_data(rva,0x11a))
  hashes=[0xbd701184,0x18e67533,0x840a9c18,0xbcacd642,0xafd53e15,0x61d07327]
  ptr=v.heap+0x20000;v.u.mem_write(ptr,struct.pack('<6I',*hashes));end=0x5000f000;sp=v.frame-8;v.q(sp,end)
  v.u.reg_write(UC_X86_REG_RSP,sp);v.u.reg_write(UC_X86_REG_RCX,ptr);v.u.reg_write(UC_X86_REG_RDX,len(hashes));v.u.reg_write(UC_X86_REG_R8,0)
  v.u.emu_start(v.game+rva,end,count=100000)
  self.assertEqual(v.u.reg_read(UC_X86_REG_RIP),end);self.assertEqual(v.u.reg_read(UC_X86_REG_RAX),v.target)
 def test_experimental02_failure_reproduced_on_correct_namespace(self):
  current=m.s.old.PLUGIN_IMAGE
  try:
   old=pefile.PE('/workspace/hipfire-longarms2/output/HipfireRDR1.red');m.s.old.PLUGIN_IMAGE=old.get_memory_mapped_image()
   v=self.fixture();ptr,_=self.path(v,0)
   oldsyms=json.loads(Path('/workspace/hipfire-longarms2/symbols.json').read_text());saved=syms['select_node'];syms['select_node']=oldsyms['select_node']
   try:self.assertEqual(self.call(v,'select_node',42,ptr),0);self.assertEqual(v.native_calls,[])
   finally:syms['select_node']=saved
  finally:m.s.old.PLUGIN_IMAGE=current
  v=self.fixture();ptr,_=self.path(v,0);self.assertEqual(self.call(v,'select_node',42,ptr),1)
 def test_global_container_and_actor_chain_are_supported_as_root_fallbacks(self):
  for root in ['global','actor']:
   v=self.fixture();ptr,_=self.path(v,0)
   v.q(v.game+0x2ab5e78,v.nodes['global'] if root=='global' else 0)
   if root=='actor':v.q(v.ctrl+0xb0,v.nodes['normal_standing'])
   self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(v.selected,v.target)
 def test_standing_resolves_exact_recorded_path_despite_other_deadeye_variants(self):
  v=self.fixture();other=v.add('other_de',0x122ac9f4,v.nodes['rifle']);v.add('other_stand',0x61d07327,other)
  ptr,_=self.path(v,0);self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(v.selected,v.target)
 def test_four_pose_passthrough_policy_for_every_weapon(self):
  for w in range(21):
   for k in range(4):
    v=self.fixture(w,k);self.assertEqual(bool(self.call(v,'should_passthrough',42)),False)
 def test_real_cover_preserves_its_original_result_for_all_weapons(self):
  for w in [4,9,13,15,17]:
   v=self.fixture(w,2);v.real_cover=3
   self.assertEqual(self.call(v,'should_passthrough',42),3)
 def test_standing_to_walking_switches_family_then_retains_active_walk(self):
  v=self.fixture();ptr,_=self.path(v,0);self.call(v,'select_node',42,ptr)
  self.assertEqual(len([c for c in v.native_calls if c[0]=='create']),1)
  descendant=v.add('fire_descendant',0x12345678,v.target);v.q(v.ctrl+0xb0,descendant)
  ptr,_=self.path(v,1);self.assertEqual(self.call(v,'select_node',42,ptr),1)
  self.assertEqual(v.selected,v.nodes['middle'])
  self.assertEqual(len([c for c in v.native_calls if c[0]=='create']),2)
  v.i(v.base+0xf7cc,42);v.i(v.base+0x24080,1);v.b(v.base+0x2407e,1)
  v.q(v.ctrl+0xb0,v.nodes['rapid_walk'])
  self.assertEqual(self.call(v,'select_node',42,ptr),1)
  self.assertEqual(len([c for c in v.native_calls if c[0]=='create']),2)
  self.assertEqual(self.call(v,'rapid_pose',42,1,0)&255,1)
 def test_crouched_longarm_keeps_mod_click_pipeline_instead_of_passthrough(self):
  for k in [2,3]:
   v=self.fixture(k=k);v.i(v.frame+0x68,42)
   # Actual early branch falls through toward weapon/input preparation,
   # rather than the old cover/passthrough exit at 4750.
   v.run(0x4020,0x4031)
   self.assertEqual(v.u.reg_read(UC_X86_REG_RAX),0)
   self.assertEqual(v.u.mem_read(v.base+0xf960,1),b'\1')
 def test_normal_cover_does_not_take_the_new_full_release_path(self):
  v=self.fixture(k=2);v.real_cover=1;self.call(v,'should_passthrough',42)
  result=[]
  def cancel():result.append(v.u.reg_read(UC_X86_REG_R8));return 0
  v.callbacks[v.base+0x1f80]=cancel
  self.call(v,'cancel_passthrough',v.frame+0x150,v.base+0x20644,1);self.assertEqual(result,[1])
 def goal_replacement_start(self,image=None):
  current=m.s.old.PLUGIN_IMAGE
  try:
   if image:m.s.old.PLUGIN_IMAGE=image
   v=HandgunTests().vm(kind=1);self.fixture(13,1,v=v);original=v.callbacks[v.base+0x15c0];v.aim_count=0
   def aim():
    original();v.aim_count+=1
    if v.aim_count==1:v.q(v.ctrl+0xb0,v.nodes['normal_standing'])
    return 0
   v.callbacks[v.base+0x15c0]=aim;v.run(0x5c94,0x5b3f);return v
  finally:m.s.old.PLUGIN_IMAGE=current
 def test_reproduced_goal_replacement_is_repaired_only_after_initial_aim(self):
  old=pefile.PE('/workspace/hipfire-longarms4/output/HipfireRDR1.red').get_memory_mapped_image()
  before=self.goal_replacement_start(old);self.assertEqual(before.getq(before.ctrl+0xb0),before.nodes['normal_standing'])
  v=self.goal_replacement_start();self.assertEqual(v.getq(v.ctrl+0xb0),v.nodes['middle'])
  self.assertEqual(self.call(v,'rapid_pose',42,1,0)&255,1)
  calls=len(v.native_calls);self.call(v,'longarm_aim',42,v.frame+0x110)
  self.assertEqual(v.aim_count,2);self.assertEqual(len(v.native_calls),calls)
 def timed(self,kind=1):
  v=self.fixture(13,kind);ptr,_=self.path(v,kind);self.call(v,'select_node',42,ptr)
  v.i(v.base+0x24080,kind);v.i(v.frame+0x6c,13);v.i(v.frame+0x76c,13)
  v.q(v.frame+0x40,1100);v.q(v.frame+0x7f0,1000);v.q(v.frame+0x7f8,1800);v.b(v.frame+0x770,1)
  return v
 def test_walking_prepare_and_cycle_deadlines_are_fixed_not_sliding(self):
  v=self.timed();v.b(v.frame+0x775,1);v.q(v.frame+0x7b0,1300);v.q(v.frame+0x800,1234)
  before=bytes(v.u.mem_read(v.weapon,0x600));self.call(v,'longarm_tick',v.frame)
  self.assertEqual(v.getq(v.frame+0x7b0),1700);self.assertEqual(v.getq(v.frame+0x7f8),2600)
  v.q(v.frame+0x40,1500);self.call(v,'longarm_tick',v.frame)
  self.assertEqual(v.getq(v.frame+0x7b0),1700);self.assertEqual(v.getq(v.frame+0x7f8),2600)
  self.assertEqual(v.getq(v.frame+0x800),1234);self.assertEqual(bytes(v.u.mem_read(v.weapon,0x600)),before)
  v.q(v.frame+0x40,2800);self.call(v,'longarm_tick',v.frame);self.assertEqual(v.getq(v.frame+0x7f8),2600)
 def test_standing_prepare_unchanged_but_rifle_cycle_wait_survives_old_timeout(self):
  v=self.timed(0);v.b(v.frame+0x775,1);v.q(v.frame+0x7b0,1300)
  self.call(v,'longarm_tick',v.frame);self.assertEqual(v.getq(v.frame+0x7b0),1300)
  v.q(v.frame+0x40,1900);v.run(0x430e,0x4321) # actual original deadline branch still waits
  v.q(v.frame+0x40,2700);v.run(0x430e,0x5998) # bounded expiry still takes the original failure route
 def test_confirmed_rifle_hold_spans_bolt_cycle_then_expires(self):
  v=self.timed(0);v.b(v.frame+0x770,0);v.q(v.frame+0x788,1000);v.q(v.base+0x24060,1750)
  self.call(v,'longarm_tick',v.frame);self.assertEqual(v.getq(v.base+0x24060),2800)
  v.q(v.frame+0x40,2000);self.call(v,'longarm_tick',v.frame);self.assertEqual(v.getq(v.base+0x24060),2800)
  v.q(v.frame+0x40,3000);self.call(v,'longarm_tick',v.frame);self.assertEqual(v.getq(v.base+0x24060),2800)
 def test_hold_extension_stops_for_empty_crouched_cancelled_or_other_weapon(self):
  for change in [lambda v:v.f(v.frame+0x828,0),lambda v:v.i(v.base+0x24080,4),lambda v:v.b(v.base+0xf960,0),lambda v:v.i(v.frame+0x76c,4)]:
   v=self.timed(0);v.b(v.frame+0x770,0);v.q(v.frame+0x788,1000);v.q(v.base+0x24060,1750);change(v)
   before=bytes(v.u.mem_read(v.frame,0x900));self.call(v,'longarm_tick',v.frame)
   self.assertEqual(v.getq(v.base+0x24060),1750);self.assertEqual(bytes(v.u.mem_read(v.frame,0x900)),before)
 def test_longarm_tick_bridge_preserves_registers_while_extending_live_attempt(self):
  v=self.timed();v.b(v.frame+0x775,1);v.q(v.frame+0x7b0,1300)
  regs=[UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RBP,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15]
  for i,r in enumerate(regs):v.u.reg_write(r,0x123456780000+i)
  for i in range(16):v.u.reg_write(UC_X86_REG_XMM0+i,(1<<100)+i)
  before=[v.u.reg_read(r) for r in regs];xmms=[v.u.reg_read(UC_X86_REG_XMM0+i) for i in range(16)]
  v.tick();self.assertEqual(before,[v.u.reg_read(r) for r in regs]);self.assertEqual(xmms,[v.u.reg_read(UC_X86_REG_XMM0+i) for i in range(16)])
  self.assertEqual(v.getq(v.frame+0x7b0),1700);self.assertEqual(v.getq(v.frame+0x7f8),2600)
  entry=next(e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress==syms['longarm_bridge'][0])
  self.assertEqual(p.get_data(entry.UnwindData,1)[0],0x21)
 def test_reload_uses_stable_weapon_after_actual_scratch_clobber(self):
  for w in range(21):
   for flag in [0,1]:
    v=m.s.old.VM();v.i(v.frame+0x6c,w);v.i(v.frame+0x76c,w)
    v.run(0x427b,0x4280) # actual original instruction reuses low byte of weapon scratch
    if flag:v.b(v.frame+0x6c,1)
    v.real_engine();v.mark();self.assertEqual(v.geti(v.base+0x63004),w)
    v.tick();self.assertEqual(v.requests,1);self.assertEqual(v.pending(),-1)
 def test_reproduces_old_autoreload_failure_with_reused_weapon_local(self):
  current=m.s.old.PLUGIN_IMAGE
  try:
   m.s.old.PLUGIN_IMAGE=pefile.PE('/workspace/hipfire-longarms5/output/HipfireRDR1.red').get_memory_mapped_image()
   v=m.s.old.VM();v.i(v.frame+0x6c,13);v.i(v.frame+0x76c,13);v.run(0x427b,0x4280)
   v.real_engine();v.mark();self.assertEqual(v.geti(v.base+0x63004),0)
   v.tick();self.assertEqual(v.requests,0)
  finally:m.s.old.PLUGIN_IMAGE=current
  v=m.s.old.VM();v.i(v.frame+0x6c,13);v.i(v.frame+0x76c,13);v.run(0x427b,0x4280)
  v.real_engine();v.mark();v.tick();self.assertEqual(v.requests,1)
 def test_reload_confirmation_actor_also_comes_from_stable_controls(self):
  v=m.s.old.VM();v.i(v.frame+0x68,99);v.mark();self.assertEqual(v.pending(),42)
 def intent_fixture(self,k=0):
  v=HandgunTests().vm(kind=k);self.fixture(13,k,v=v)
  ptr,_=self.path(v,k);self.call(v,'select_node',42,ptr)
  v.i(v.base+0xf7cc,42);v.i(v.base+0x24080,k);v.b(v.base+0x2407e,1)
  v.i(v.frame+0x76c,13);v.f(v.frame+0x828,5)
  v.q(v.frame+0x40,1000);v.request_calls=0
  def request():
   out=v.u.reg_read(UC_X86_REG_RCX);v.request_calls+=1
   v.u.mem_write(out,struct.pack('<iiff',1,8,-1,0));return out
  def clear():
   v.calls.append(('clear_shoot',));v.b(v.base+0x2407c,0);return 0
  v.callbacks[v.base+0xd3f0]=request;v.callbacks[v.base+0x1dd0]=clear
  return v
 def test_longarm_standing_backlog_from_07_expires_in_08(self):
  def trial(old=False):
   current=m.s.old.PLUGIN_IMAGE
   try:
    if old:m.s.old.PLUGIN_IMAGE=pefile.PE('/workspace/hipfire-longarms7/output/HipfireRDR1.red').get_memory_mapped_image()
    v=self.fixture(k=0);v.i(v.frame+0x76c,13);self.put_queue(v,[14,15,16,17]);self.pre(v,1000);self.pre(v,1500)
    return self.queued_ids(v)
   finally:m.s.old.PLUGIN_IMAGE=current
  self.assertEqual(trial(True),[14,15,16,17]);self.assertEqual(trial(),[])
 def test_longarm_expiry_prunes_wrapped_queue_but_preserves_fresh_click(self):
  for k in [0,1]:
   v=self.intent_fixture(k);self.put_queue(v,[11,12],63);self.pre(v,1000)
   self.put_queue(v,[11,12,13],63);self.pre(v,1200);self.pre(v,1251)
   self.assertEqual(self.queued_ids(v),[13])
 def test_unaccepted_cycle_wait_is_abandoned_without_releasing_hip_pose(self):
  v=self.intent_fixture();self.put_queue(v,[14,15]);v.b(v.frame+0x770,1);v.b(v.frame+0x771,1)
  v.b(v.base+0x2407c,1);v.b(v.base+0x2407d,1);v.b(v.frame+0x152,1)
  node=v.getq(v.ctrl+0xb0);before=bytes(v.u.mem_read(v.weapon,0x600))
  self.call(v,'longarm_controls',v.frame);v.q(v.frame+0x40,1401)
  self.call(v,'longarm_controls',v.frame)
  self.assertEqual(v.u.mem_read(v.frame+0x770,2),b'\0\0');self.assertEqual(self.queued_ids(v),[15])
  self.assertIn(('clear_shoot',),v.calls);self.assertEqual(v.u.mem_read(v.base+0x2407d,1),b'\1')
  self.assertEqual(v.getq(v.ctrl+0xb0),node);self.assertEqual(v.geti(v.base+0xf900)&1,0)
  self.assertEqual(bytes(v.u.mem_read(v.weapon,0x600)),before)
  self.pre(v,1402);self.assertEqual(self.queued_ids(v),[])
 def test_engine_accepted_round_is_preserved_until_confirmation(self):
  v=self.intent_fixture();self.put_queue(v,[14]);v.b(v.frame+0x770,1);v.b(v.frame+0x777,1)
  self.call(v,'longarm_controls',v.frame);v.q(v.frame+0x40,1600);self.call(v,'longarm_controls',v.frame)
  self.assertEqual(self.queued_ids(v),[14]);self.assertEqual(v.u.mem_read(v.frame+0x770,1),b'\1')
 def test_held_rifle_tracks_new_target_without_creating_fire_or_restarting_node(self):
  for k in range(4):
   v=self.intent_fixture(k);v.b(v.base+0x2407d,1);v.u.mem_write(v.base+0x24070,struct.pack('<fff',0,0,100))
   v.live_plan=struct.pack('<ffffIB3x',100,20,0,90,0,1);v.calls=[]
   node=v.getq(v.ctrl+0xb0);before=bytes(v.u.mem_read(v.weapon,0x600))
   self.call(v,'longarm_controls',v.frame)
   self.assertEqual(bytes(v.u.mem_read(v.base+0x24070,12)),v.live_plan[:12])
   self.assertEqual(v.calls,[('aim',v.live_plan[:12])]);self.assertEqual(v.request_calls,0)
   self.assertEqual(v.getq(v.ctrl+0xb0),node);self.assertEqual(bytes(v.u.mem_read(v.weapon,0x600)),before)
 def test_pending_goal_tracks_new_target_and_accepted_goal_is_not_reissued(self):
  for accepted in [False,True]:
   v=self.intent_fixture();v.b(v.base+0x2407d,1);v.b(v.base+0x2407c,1);v.b(v.frame+0x770,1);v.b(v.frame+0x777,int(accepted))
   v.live_plan=struct.pack('<ffffIB3x',100,20,0,90,0,1);v.calls=[]
   self.call(v,'longarm_controls',v.frame)
   self.assertEqual([x[0] for x in v.calls],['aim']+([] if accepted else ['shoot_goal']))
 def test_new_aim_waits_for_engine_update_and_full_alignment_before_request(self):
  v=self.intent_fixture();v.b(v.base+0x2407d,1);v.u.mem_write(v.base+0x24070,struct.pack('<fff',0,0,100))
  v.live_plan=struct.pack('<ffffIB3x',100,20,0,90,0,1);self.call(v,'longarm_queue',v.frame,0)
  out=v.heap+0x21000;self.call(v,'controlled_request',out,42)
  self.assertEqual(v.geti(out),-3);self.assertEqual(v.request_calls,0)
  v.q(v.frame+0x40,1051);v.f(v.weapon+0x368,.28);self.call(v,'controlled_request',out,42)
  self.assertEqual(v.geti(out),-3);self.assertEqual(v.request_calls,0)
  v.f(v.weapon+0x368,0);self.call(v,'controlled_request',out,42)
  self.assertEqual(v.geti(out),1);self.assertEqual(v.request_calls,1)
 def test_input_trigger_obeys_same_alignment_gate_as_internal_request(self):
  v=self.intent_fixture();v.b(v.frame+0x770,1);v.b(v.frame+0x771,1);v.b(v.frame+0x152,1);v.i(v.base+0xf900,7)
  v.f(v.weapon+0x368,.28);self.call(v,'longarm_controls',v.frame)
  self.assertEqual(v.geti(v.base+0xf900)&1,0);self.assertEqual(v.u.mem_read(v.frame+0x771,1),b'\1')
 def test_waiting_for_alignment_preserves_already_released_input_frames(self):
  v=self.intent_fixture();v.b(v.frame+0x770,1);v.b(v.frame+0x775,1)
  v.b(v.frame+0x152,0);v.i(v.base+0xf900,4);v.i(v.frame+0x7d0,3)
  v.f(v.weapon+0x368,1);self.call(v,'longarm_controls',v.frame)
  self.assertEqual(v.geti(v.frame+0x7d0),3)
 def test_failed_live_target_suppresses_new_request(self):
  v=self.intent_fixture();v.bad_plan=True;self.call(v,'longarm_queue',v.frame,0)
  out=v.heap+0x21000;self.call(v,'controlled_request',out,42)
  self.assertEqual(v.geti(out),-3);self.assertEqual(v.request_calls,0)
 def test_handgun_and_sawedoff_requests_preserve_original_behavior(self):
  for w in list(range(8))+[15]:
   v=self.intent_fixture();v.i(v.frame+0x76c,w);self.call(v,'longarm_queue',v.frame,0)
   v.f(v.weapon+0x368,1);out=v.heap+0x21000;self.call(v,'controlled_request',out,42)
   self.assertEqual(v.geti(out),1);self.assertEqual(v.request_calls,1)
 def test_disabled_controls_and_invalid_modes_do_not_update_aim(self):
  for off,val in [(0xf960,0),(0xf7c8,0),(0x24080,4),(0x24080,-1)]:
   v=self.intent_fixture();v.live_plan=struct.pack('<ffffIB3x',100,20,0,90,0,1);v.calls=[]
   if off==0x24080:v.i(v.base+off,val)
   else:v.b(v.base+off,val)
   before=bytes(v.u.mem_read(v.frame,0x900));self.call(v,'longarm_controls',v.frame)
   self.assertEqual(v.calls,[]);self.assertEqual(bytes(v.u.mem_read(v.frame,0x900)),before)
 def test_live_target_unwind_preserves_nonvolatile_vector_registers(self):
  start=syms['_ZL14refresh_targetPh'][0]
  entry=next(e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress==start)
  raw=p.get_data(entry.UnwindData,100);count=raw[2];index=0;saves={}
  while index<count:
   offset,op=raw[4+index*2:6+index*2];index+=1;kind=op&15
   if kind==8:
    saves[op>>4]=struct.unpack_from('<H',raw,4+index*2)[0]*16;index+=1
   elif kind==1:index+=1 if op>>4==0 else 2
  self.assertEqual(saves,{6:0x50,7:0x60,8:0x70,9:0x80})
  self.assertGreaterEqual(raw[1],0x41)
 def test_crouched_locomotion_accepts_ordinary_walk_and_run_children(self):
  v=self.fixture(k=3);ptr,_=self.path(v,3);self.call(v,'select_node',42,ptr)
  self.assertEqual(v.selected,v.nodes['crouch_hold'])
  for name in ['ordinary_crouch_walk','ordinary_crouch_run','crouch_common']:
   v.q(v.ctrl+0xb0,v.nodes[name]);self.assertEqual(self.call(v,'playing_node',42,ptr),1)
  v.q(v.ctrl+0xb0,v.nodes['crouched_moving']);self.assertEqual(self.call(v,'playing_node',42,ptr),0)
 def test_missing_ordinary_crouch_family_does_not_guess_deadeye_path(self):
  for k in [2,3]:
   v=self.fixture(k=k);v.i(v.nodes['crouch_hold']+0x38,0x1234);ptr,_=self.path(v,k)
   self.assertEqual(self.call(v,'select_node',42,ptr),0);self.assertEqual(v.native_calls,[])
 def test_actual_crouched_continuation_uses_current_aim_and_single_shoot_goal(self):
  for k in [2,3]:
   v=HandgunTests().vm(kind=k);self.fixture(13,k,v=v);v.run(0x5c94,0x5b3f)
   self.assertEqual(v.geti(v.base+0x24080),k);v.calls=[]
   v.u.mem_write(v.frame+0x110,struct.pack('<ffff',110,120,130,37))
   v.u.reg_write(UC_X86_REG_RAX,struct.unpack('<I',struct.pack('<f',130))[0]);v.u.reg_write(UC_X86_REG_RDX,v.getq(v.frame+0x110))
   v.run(0x5ab3,0x5b3f)
   self.assertEqual([c[0] for c in v.calls],['aim','shoot_goal'])
   self.assertEqual(v.calls[0][1],struct.pack('<fff',110,120,130))
 def test_initial_crouch_aim_reasserts_its_own_ordinary_family_after_replacement(self):
  for k in [2,3]:
   v=HandgunTests().vm(kind=k);self.fixture(13,k,v=v)
   original=v.callbacks[v.base+0x15c0]
   def aim():
    original();v.q(v.ctrl+0xb0,v.nodes['normal_standing']);return 0
   v.callbacks[v.base+0x15c0]=aim;v.run(0x5c94,0x5b3f)
   self.assertEqual(v.getq(v.ctrl+0xb0),v.nodes['crouch_hold'])
   self.assertEqual(self.call(v,'rapid_pose',42,k&1,1)&255,1)
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
