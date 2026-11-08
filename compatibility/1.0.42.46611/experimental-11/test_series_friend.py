import sys,struct,unittest,importlib.util
from pathlib import Path
sys.path.insert(0,'/workspace/hipfire-reload/python-deps')
import pefile
from unicorn.x86_const import *
R=Path(__file__).parent
spec=importlib.util.spec_from_file_location('reload_tests','/workspace/hipfire-compat11/test_reload_friend.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
P=pefile.PE(str(R/'output/HipfireRDR1.red'))
old.PLUGIN_IMAGE=P.get_memory_mapped_image()
class SeriesTests(unittest.TestCase):
 def vm(self,kind=0,valid=True,base=0x1cf0c0000):
  v=old.VM(base);v.kind=kind;v.calls=[];v.valid=valid
  v.callbacks[base+0x1490]=lambda:kind
  def node():
   ptr=v.u.reg_read(UC_X86_REG_RDX);name=bytes(v.u.mem_read(ptr,200)).split(b'\0')[0].decode();v.calls.append(('node',name));return int(v.valid)
  def heading():
   value=struct.unpack('<f',struct.pack('<I',v.u.reg_read(UC_X86_REG_XMM1)&0xffffffff))[0];v.calls.append(('heading',value));return 0
  def aim():v.calls.append(('aim',bytes(v.u.mem_read(v.u.reg_read(UC_X86_REG_RDX),12))));return 0
  def shootgoal():v.calls.append(('shoot_goal',bytes(v.u.mem_read(v.u.reg_read(UC_X86_REG_RDX),12))));return 0
  v.callbacks[base+0xd730]=node;v.callbacks[base+0xd9a0]=heading;v.callbacks[base+0x15c0]=aim;v.callbacks[base+0x1580]=shootgoal
  v.f(v.frame+0x110,10);v.f(v.frame+0x114,20);v.f(v.frame+0x118,30);v.f(v.frame+0x11c,37);v.q(v.frame+0x50,v.frame+0x110)
  return v
 def test_standing_goal_backend(self):
  for base in [0x1cf0c0000,0x180000000,0x7ff800000000]:
   v=self.vm(base=base);v.run(0x5c94,0x5b3f)
   self.assertEqual(v.calls[0],('node','default_character_Main\\Gunplay\\Pistol\\DeadEye\\PistolHoldStand'))
   self.assertEqual(v.calls[1],('heading',37));self.assertEqual(v.calls[2][0],'aim')
   self.assertEqual(v.calls[2][1],struct.pack('<fff',10,20,30))
   self.assertEqual(v.geti(base+0xf7cc),42);self.assertEqual(v.geti(base+0x24080),0)
   self.assertEqual(bytes(v.u.mem_read(base+0x2407e,2)),b'\x01\x00')
 def test_failed_node_has_no_aim_or_request(self):
  v=self.vm(valid=False);v.run(0x5c94,0x5f1b);self.assertEqual(len(v.calls),1);self.assertEqual(v.geti(v.base+0xf7cc),-1)
 def test_moving_crouch_routes_unchanged(self):
  for kind,suffix in [(1,'PistolHoldRun'),(2,'PistolHoldStand'),(3,'PistolHoldRun')]:
   v=self.vm(kind);v.run(0x5c94,0x5b3f)
   self.assertTrue(v.calls[0][1].endswith(suffix));self.assertEqual(v.calls[1][0],'aim');self.assertEqual(v.geti(v.base+0x24080),kind)
 def test_original_continuation_keeps_node_and_current_target(self):
  v=self.vm();v.run(0x5c94,0x5b3f);v.calls=[]
  v.f(v.frame+0x110,110);v.f(v.frame+0x114,120);v.f(v.frame+0x118,130)
  # Execute the actual pre-existing continuation branch with a fresh plan.
  v.u.reg_write(UC_X86_REG_RAX,struct.unpack('<I',struct.pack('<f',130))[0])
  v.u.reg_write(UC_X86_REG_RDX,v.getq(v.frame+0x110));v.run(0x5ab3,0x5b3f)
  self.assertEqual([c[0] for c in v.calls],['aim','shoot_goal'])
  self.assertEqual(v.calls[0][1],struct.pack('<fff',110,120,130))
 def test_bounded_idle_window_and_next_shot_interval(self):
  v=self.vm();v.u.reg_write(UC_X86_REG_RAX,1000);v.u.reg_write(UC_X86_REG_RCX,1200);v.q(v.frame+0x40,1100)
  v.run(0x4dc6,0x48f9)
  self.assertEqual(v.getq(v.base+0x24060),1850)
  self.assertEqual(v.getq(v.frame+0x800),1550)
 def test_binary_scope_and_pe_layout(self):
  stable=pefile.PE('/workspace/hipfire-reload/output/HipfireRDR1.red')
  for a,b in zip(stable.sections,P.sections):
   x=bytearray(a.get_data());y=bytearray(b.get_data())
   if a.VirtualAddress==0x1000:
    for rva,size in [(0x5cad,6),(0x4dda,7)]:
     o=rva-0x1000;y[o:o+size]=x[o:o+size]
   self.assertEqual(x,y,a.Name)
  end=0x1000
  for s in P.sections:
   self.assertEqual(s.VirtualAddress,end,s.Name);end=(end+max(s.Misc_VirtualSize,s.SizeOfRawData)+4095)//4096*4096
  self.assertEqual(end,P.OPTIONAL_HEADER.SizeOfImage);self.assertTrue(P.verify_checksum());self.assertFalse(P.get_warnings())
if __name__=='__main__':
 suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(old.Tests),unittest.defaultTestLoader.loadTestsFromTestCase(SeriesTests)])
 result=unittest.TextTestRunner(verbosity=2).run(suite);sys.exit(not result.wasSuccessful())
