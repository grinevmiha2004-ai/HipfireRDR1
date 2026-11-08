import sys,struct,json,unittest,importlib.util
from pathlib import Path
sys.path.insert(0,'/workspace/hipfire-reload/python-deps')
import pefile
from unicorn.x86_const import *
R=Path(__file__).parent
spec=importlib.util.spec_from_file_location('baseline','/workspace/hipfire-series4/test_rapid.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=pefile.PE(str(R/'output/HipfireRDR1.red'));m.s.old.PLUGIN_IMAGE=p.get_memory_mapped_image()
syms=json.loads((R/'symbols.json').read_text());data=syms['choice'][0]
class HandgunTests(m.s.SeriesTests):
 def vm(self,*args,**kwargs):
  v=super().vm(*args,**kwargs);v.callbacks[v.base+0xd870]=lambda:4;return v
class LongarmTests(m.GuardTests):
 def call(self,v,name,*args):
  caller=0x5000f000;sp=v.frame-8;v.q(sp,caller);v.u.reg_write(UC_X86_REG_RSP,sp)
  for reg,value in zip([UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9],args):v.u.reg_write(reg,value)
  v.u.emu_start(v.base+syms[name][0],caller,count=50000);self.assertEqual(v.u.reg_read(UC_X86_REG_RIP),caller)
  return v.u.reg_read(UC_X86_REG_RAX)
 def setup_actor(self,w=8,base=0x1cf0c0000):
  v=self.vm(base);v.model=w;v.selects=[];v.plays=[];v.accept=True;v.play=True
  v.callbacks[v.base+0xd870]=lambda:v.model
  def readtext(ptr):return bytes(v.u.mem_read(ptr,256)).split(b'\0')[0].decode()
  def select():
   path=readtext(v.u.reg_read(UC_X86_REG_RDX));v.selects.append(path)
   return int(v.accept(path) if callable(v.accept) else v.accept)
  def playing():
   path=readtext(v.u.reg_read(UC_X86_REG_RDX));v.plays.append(path);return int(v.play)
  v.callbacks[v.base+0xd730]=select;v.callbacks[v.base+0xd7f0]=playing
  return v
 def path(self,v,k):
  ptr=v.heap+0x20000
  # Use the actual four existing paths, not reconstructed strings.
  rv=[0x202c0,0x201b8,0x20200,0x20260][k];path=bytes(p.get_data(rv,256)).split(b'\0')[0]
  v.u.mem_write(ptr,path+b'\0');return ptr,path.decode()
 def test_all_thirteen_longarms_all_four_poses_route_to_longarm_nodes(self):
  for w in range(8,21):
   for k in range(4):
    v=self.setup_actor(w);ptr,_=self.path(v,k)
    self.assertEqual(self.call(v,'select_node',42,ptr),1)
    path=v.selects[-1];self.assertNotIn('Pistol',path)
    self.assertIn('Shotgun' if 15<=w<=18 else 'Rifle',path)
    self.assertTrue(path.endswith('HoldRun' if k in [1,3] else 'HoldStand'))
    self.assertEqual('Crouch' in path,k>=2)
    self.assertEqual(self.call(v,'playing_node',42,ptr),1);self.assertEqual(v.plays[-1],path)
 def test_handgun_select_and_query_preserve_exact_original_paths(self):
  for w in range(8):
   for k in range(4):
    v=self.setup_actor(w);ptr,path=self.path(v,k)
    self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(v.selects,[path])
    self.assertEqual(self.call(v,'playing_node',42,ptr),1);self.assertEqual(v.plays,[path])
 def test_missing_nodes_refuse_and_never_use_handgun_fallback(self):
  for w in [8,12,16,19]:
   v=self.setup_actor(w);v.accept=False;ptr,_=self.path(v,0)
   self.assertEqual(self.call(v,'select_node',42,ptr),0);self.assertEqual(len(v.selects),3)
   self.assertTrue(all('Pistol' not in path for path in v.selects))
   self.assertEqual(self.call(v,'playing_node',42,ptr),0);self.assertEqual(v.plays,[])
   self.assertEqual(self.call(v,'rapid_pose',42,0,0)&255,0)
 def test_accepted_family_cached_and_unknown_weapon_transient_preserved(self):
  v=self.setup_actor(17);v.accept=lambda path:'\\Rifle\\' in path;ptr,_=self.path(v,0)
  self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(len(v.selects),2)
  selected=v.selects[-1];v.model=-1
  self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(v.selects[-1],selected)
  self.assertEqual(self.call(v,'playing_node',42,ptr),1)
 def test_weapon_and_actor_change_cannot_reuse_cached_node(self):
  v=self.setup_actor(16);ptr,_=self.path(v,0);self.call(v,'select_node',42,ptr)
  v.model=8;self.assertEqual(self.call(v,'playing_node',42,ptr),0)
  self.call(v,'select_node',42,ptr);self.assertIn('\\Rifle\\',v.selects[-1])
  self.assertEqual(self.call(v,'playing_node',99,ptr),0)
 def test_release_root_never_rewritten(self):
  v=self.setup_actor(12);ptr=v.heap+0x20000;v.u.mem_write(ptr,b'default_character_Main\0')
  self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(v.selects,['default_character_Main'])
 def test_real_rapid_hook_and_autoreload_all_new_weapon_ids(self):
  for w in range(8,21):
   v=self.vm();v.i(v.frame+0x6c,w);v.i(v.frame+0x76c,w)
   v.i(v.base+0xf7cc,-1);v.f(v.frame+0x828,0);v.mark();v.tick();self.assertEqual(v.requests,1)
   v=self.vm();v.i(v.frame+0x6c,w);v.i(v.frame+0x76c,w)
   v.tick();self.assertEqual(self.condition(v),1)
 def test_real_start_branch_for_each_longarm_and_pose(self):
  for w in range(8,21):
   for k in range(4):
    v=HandgunTests().vm(kind=k);v.callbacks[v.base+0xd870]=lambda:w
    v.run(0x5c94,0x5b3f)
    self.assertNotIn('Pistol',v.calls[0][1]);self.assertEqual(v.geti(v.base+0xf7cc),42)
    self.assertEqual(v.geti(v.base+0x24080),k)
    self.assertIn('aim',[call[0] for call in v.calls]);self.assertEqual(bytes(v.u.mem_read(v.base+0x2407e,2)),b'\x01\x00')
 def test_real_start_refuses_missing_longarm_nodes_without_aim_or_owned_action(self):
  for k in range(4):
   v=HandgunTests().vm(kind=k,valid=False);v.callbacks[v.base+0xd870]=lambda:12
   v.run(0x5c94,0x5f1b)
   self.assertEqual([call[0] for call in v.calls],['node','node','node'])
   self.assertEqual(v.geti(v.base+0xf7cc),-1)
 def test_clip_filter_only_accepts_matching_hip_rapid_family_and_posture(self):
  v=self.setup_actor();ptr=v.heap+0x20000
  for name,moving,crouched,valid in [('hum_rfl_rpd_stn_aim',0,0,True),('hum_sht_hip_rpd_run_fir',1,0,True),('hum_crc_rfl_rpd_stn_fir',1,1,True),('hum_ptl_rpd_stn_fir',0,0,False),('hum_rfl_aim_stn',0,0,False),('hum_rfl_rpd_stn_aim',0,1,False),('hum_rfl_rpd_stn_aim',1,0,False),('hum_rfl_rpd_run_fir',0,0,False)]:
   v.u.mem_write(ptr,name.encode()+b'\0');self.assertEqual(bool(self.call(v,'clip_matches',ptr,moving,crouched)&255),valid,name)
 def test_relocated_extension_has_no_static_absolute_pointers(self):
  for base in [0x1cf0c0000,0x180000000,0x7ff800000000]:
   v=self.setup_actor(13,base);ptr,_=self.path(v,0)
   self.assertEqual(self.call(v,'select_node',42,ptr),1);self.assertEqual(self.call(v,'playing_node',42,ptr),1)
 def test_frame_weapon_gate_accepts_firearms_excludes_other_items(self):
  for w in list(range(-2,39)):
   v=self.vm();v.i(v.frame+0x6c,w);end=0x4052 if 0<=w<=20 else 0x4812
   v.run(0x4047,end)
 def test_final_pe_and_original_sections(self):
  src=Path('/workspace/hipfire-series4/output/HipfireRDR1.red').read_bytes();a=pefile.PE(data=src);allowed=set()
  for patch in json.loads((R/'patch-report.json').read_text()):
   off=a.get_offset_from_rva(int(patch['rva'],16));allowed.update(range(off,off+len(bytes.fromhex(patch['before']))))
  for before,after in zip(a.sections,p.sections):
   self.assertEqual(before.VirtualAddress,after.VirtualAddress)
   x=before.get_data();y=after.get_data();self.assertEqual(len(x),len(y))
   self.assertTrue(all(before.PointerToRawData+j in allowed for j,(u,v) in enumerate(zip(x,y)) if u!=v),before.Name)
  end=0x1000
  for section in p.sections:
   self.assertEqual(section.VirtualAddress,end);end=(end+max(section.Misc_VirtualSize,section.SizeOfRawData)+4095)//4096*4096
  self.assertEqual(end,p.OPTIONAL_HEADER.SizeOfImage);self.assertTrue(p.verify_checksum());self.assertFalse(p.get_warnings())
  entries={e.struct.BeginAddress:e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION}
  for name,(start,size) in syms.items():
   if 0x68000<=start<0x6a000:self.assertEqual(entries[start].EndAddress,start+size)
# The section equality test above supersedes previous historical equality tests.
suite=unittest.TestSuite()
for cls,excluded in [(m.s.old.Tests,{'test_original_sections_preserved'}),(HandgunTests,{'test_binary_scope_and_pe_layout'}),(LongarmTests,set())]:
 for name in unittest.defaultTestLoader.getTestCaseNames(cls):
  if name not in excluded:suite.addTest(cls(name))
r=unittest.TextTestRunner(verbosity=2).run(suite);sys.exit(not r.wasSuccessful())
