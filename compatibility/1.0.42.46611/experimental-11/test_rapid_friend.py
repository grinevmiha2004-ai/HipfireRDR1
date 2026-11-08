import sys,importlib.util,struct,unittest
from pathlib import Path
sys.path.insert(0,'/workspace/hipfire-reload/python-deps')
import pefile
from unicorn import UcError
from unicorn.x86_const import *
R=Path(__file__).parent
spec=importlib.util.spec_from_file_location('series1','/workspace/hipfire-compat11/test_series_friend.py');s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
P=pefile.PE(str(R/'output/HipfireRDR1.red'));s.old.PLUGIN_IMAGE=P.get_memory_mapped_image()
class GuardTests(unittest.TestCase):
 def vm(self,base=0x1cf0c0000):
  v=s.old.VM(base);v.clock=1100
  # Install real predicate bytes from the uploaded EXE, not a replacement model.
  v.u.mem_write(v.game+0xca8bd0,s.old.GAME_PE.get_data(0xca8bd0,34))
  self.assertEqual(struct.unpack('<Q',s.old.GAME_PE.get_data(0x1d42af8,8))[0],v.game+0xca8bd0)
  v.q(v.game+0x1d42af8,v.game+0xca8bd0)
  def ptr():
   try:return v.getq(v.u.reg_read(UC_X86_REG_RCX))
   except UcError:return 0
  def byte():
   try:v.u.mem_write(v.u.reg_read(UC_X86_REG_RDX),bytes(v.u.mem_read(v.u.reg_read(UC_X86_REG_RCX),1)));return 1
   except UcError:return 0
  def protect():v.i(v.u.reg_read(UC_X86_REG_R9),2);return 1
  v.callbacks[base+0x19a0]=ptr;v.callbacks[base+0x18a0]=byte
  v.callbacks[0x50000400]=protect;v.callbacks[0x50000500]=lambda:v.clock
  v.q(base+0x362f8,0x50000400);v.q(base+0x362a8,0x50000500)
  v.i(base+0xf7cc,42);v.i(base+0x24080,0);v.b(base+0x2407e,1);v.b(base+0x2407f,0)
  v.f(v.frame+0x828,8);v.q(base+0x24060,2000);v.q(v.frame+0x40,1100)
  return v
 def condition(self,v,character=None):
  ctx=v.heap+0x11000;v.q(ctx+0x30,character or v.character)
  slot=v.getq(v.game+0x1d42af8);sp=v.frame-8;v.q(sp,0x5000f000)
  v.u.reg_write(UC_X86_REG_RSP,sp);v.u.reg_write(UC_X86_REG_RCX,v.heap+0x12000);v.u.reg_write(UC_X86_REG_RDX,ctx)
  v.u.emu_start(slot,0x5000f000,count=10000)
  self.assertEqual(v.u.reg_read(UC_X86_REG_RIP),0x5000f000)
  return v.u.reg_read(UC_X86_REG_RAX)&255
 def test_override_real_predicate_for_local_actor_only(self):
  for base in [0x1cf0c0000,0x180000000,0x7ff800000000]:
   v=self.vm(base);self.assertEqual(self.condition(v),0);before=bytes(v.u.mem_read(v.weapon,0x600))
   v.tick();self.assertEqual(v.getq(v.game+0x1d42af8),base+0x65000);self.assertEqual(self.condition(v),1)
   self.assertEqual(bytes(v.u.mem_read(v.weapon,0x600)),before)
   foreign=v.heap+0x14000;v.q(foreign+0xaa8,v.manager);self.assertEqual(self.condition(v,foreign),0)
 def test_original_positive_result_preserved(self):
  v=self.vm();v.tick();v.b(v.base+0xf960,0);v.b(v.weapon+0x5d8,2);self.assertEqual(self.condition(v),1)
 def test_cancelled_controls_and_heartbeat(self):
  changes=[lambda v:v.b(v.base+0xf960,0),lambda v:v.b(v.base+0xf7c8,0),lambda v:v.i(v.base+0xf7cc,-1),lambda v:v.i(v.base+0x24080,4),lambda v:v.b(v.base+0x2407e,0),lambda v:setattr(v,'clock',1301)]
  for change in changes:
   v=self.vm();v.tick();change(v);self.assertEqual(self.condition(v),0)
 def test_empty_or_expired_hold_clears_guard(self):
  for off,empty in [(0x828,True),(0x40,False)]:
   v=self.vm();v.tick()
   if empty:v.f(v.frame+off,0)
   else:v.q(v.base+0x24060,1100)
   v.tick();self.assertEqual(self.condition(v),0)
 def test_signature_or_existing_hook_not_overwritten(self):
  for kind in ['signature','slot']:
   v=self.vm()
   if kind=='signature':v.u.mem_write(v.game+0xca8bd0,b'\x90')
   else:v.q(v.game+0x1d42af8,0x50009900)
   before=v.getq(v.game+0x1d42af8);v.tick();self.assertEqual(v.getq(v.game+0x1d42af8),before);self.assertEqual(v.getq(v.base+0x67008),0)
 def test_standing_interval_restored_after_confirmation(self):
  v=self.vm();v.q(v.frame+0x7f0,900);v.q(v.frame+0x788,1050);v.q(v.frame+0x800,1450);v.tick()
  self.assertEqual(v.getq(v.frame+0x800),1250)
 def test_all_four_poses(self):
  for kind in range(4):
   v=self.vm();v.i(v.base+0x24080,kind);before=bytes(v.u.mem_read(v.weapon,0x600));v.tick()
   self.assertEqual(self.condition(v),1)
   self.assertEqual(bytes(v.u.mem_read(v.weapon,0x600)),before)
   foreign=v.heap+0x14000;v.q(foreign+0xaa8,v.manager);self.assertEqual(self.condition(v,foreign),0)
 def test_mode_changes_within_existing_series(self):
  v=self.vm();v.tick()
  for kind in [1,3,2,0,2,3,1,0]:
   v.i(v.base+0x24080,kind);v.tick();self.assertEqual(self.condition(v),1)
  v.i(v.base+0xf7cc,-1);self.assertEqual(self.condition(v),0)
 def test_all_pose_intervals_match_standing(self):
  for kind in range(4):
   v=self.vm();v.i(v.base+0x24080,kind);v.q(v.frame+0x7f0,900);v.q(v.frame+0x788,1050);v.q(v.frame+0x800,1450);v.tick()
   self.assertEqual(v.getq(v.frame+0x800),1250)
 def test_unsupported_pose_kinds_refuse_override(self):
  for kind in [-1,4,255]:
   v=self.vm();v.i(v.base+0x24080,kind);v.tick();self.assertEqual(self.condition(v),0)
 def test_preparing_active_shot_keeps_permission_in_all_poses(self):
  for kind in range(4):
   v=self.vm();v.i(v.base+0x24080,kind);v.b(v.frame+0x770,1);v.q(v.frame+0x7f8,1900);v.tick();self.assertEqual(self.condition(v),1)
 def put_queue(self,v,ids,head=0):
  v.q(v.frame+0x758,head);v.q(v.frame+0x760,len(ids))
  for i,id in enumerate(ids):
   slot=(head+i)&63
   v.u.mem_write(v.frame+0x158+slot*24,struct.pack('<ffffIB3x',id+.1,id+.2,id+.3,37,id,1))
 def queued_ids(self,v):
  head=v.getq(v.frame+0x758);count=v.getq(v.frame+0x760)
  return [v.geti(v.frame+0x158+((head+i)&63)*24+16) for i in range(count)]
 def pre(self,v,now):
  v.u.reg_write(UC_X86_REG_RAX,now);v.run(0x3aed,0x3af2)
 def test_unstarted_queue_expires_in_three_poses(self):
  for kind in [1,2,3]:
   v=self.vm();v.i(v.base+0x24080,kind);self.put_queue(v,[11,12,13]);self.pre(v,1000)
   self.pre(v,1400);self.assertEqual(self.queued_ids(v),[11,12,13])
   self.pre(v,1401);self.assertEqual(self.queued_ids(v),[])
 def test_waiting_head_is_never_expired(self):
  v=self.vm();v.i(v.base+0x24080,2);v.b(v.frame+0x770,1);self.put_queue(v,[11,12,13]);self.pre(v,1000);self.pre(v,1600)
  self.assertEqual(self.queued_ids(v),[11]);self.assertEqual(v.u.mem_read(v.frame+0x770,1)[0],1)
 def test_standing_fifo_preserved_for_same_timing(self):
  v=self.vm();self.put_queue(v,[11,12,13]);self.pre(v,1000);self.pre(v,5000)
  self.assertEqual(self.queued_ids(v),[11,12,13])
 def test_wrapped_fifo_compacts_and_original_pop_still_works(self):
  v=self.vm();v.i(v.base+0x24080,3);v.b(v.frame+0x770,1);self.put_queue(v,[63,64],63);self.pre(v,1000)
  self.put_queue(v,[63,64,65],63);self.pre(v,1300);fresh=bytes(v.u.mem_read(v.frame+0x158+24,24));self.pre(v,1450)
  self.assertEqual(self.queued_ids(v),[63,65]);self.assertEqual(bytes(v.u.mem_read(v.frame+0x158,24)),fresh)
  v.u.reg_write(UC_X86_REG_RDX,2);v.run(0x4d20,0x4d48)
  self.assertEqual(self.queued_ids(v),[65]);self.assertEqual(v.getq(v.frame+0x758),0)
 def test_slow_individual_clicks_do_not_expire_fresh_intent(self):
  v=self.vm();v.i(v.base+0x24080,1)
  for id,now in enumerate([1000,1700,2400,3100],1):
   self.put_queue(v,[id]);self.pre(v,now);self.assertEqual(self.queued_ids(v),[id]);self.pre(v,now+200);self.assertEqual(self.queued_ids(v),[id])
   self.put_queue(v,[])
 def test_cancel_and_new_series_do_not_reuse_old_birth_time(self):
  v=self.vm();v.i(v.base+0x24080,2);self.put_queue(v,[1]);self.pre(v,1000)
  v.i(v.base+0xf7cc,-1);self.pre(v,1500);self.assertEqual(self.queued_ids(v),[1])
  v.i(v.base+0xf7cc,42);self.pre(v,1600);self.assertEqual(self.queued_ids(v),[1]);self.pre(v,2001);self.assertEqual(self.queued_ids(v),[])
 def test_pre_bridge_preserves_registers_and_timestamp(self):
  regs=[UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RBP,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15]
  for base in [0x1cf0c0000,0x180000000,0x7ff800000000]:
   v=self.vm(base);v.i(v.base+0x24080,1);self.put_queue(v,[11,12])
   for i,reg in enumerate(regs):v.u.reg_write(reg,1000+i)
   for i in range(16):v.u.reg_write(UC_X86_REG_XMM0+i,(1<<100)+i)
   before=[v.u.reg_read(reg) for reg in regs];xmms=[v.u.reg_read(UC_X86_REG_XMM0+i) for i in range(16)]
   self.pre(v,1000);self.assertEqual(v.getq(v.frame+0x40),1000)
   self.assertEqual(before,[v.u.reg_read(reg) for reg in regs]);self.assertEqual(xmms,[v.u.reg_read(UC_X86_REG_XMM0+i) for i in range(16)])
 def test_final_pe_and_original_sections(self):
  old=pefile.PE('/workspace/hipfire-series/output/HipfireRDR1.red')
  for a,b in zip(old.sections,P.sections):
   x=bytearray(a.get_data());y=bytearray(b.get_data())
   if a.VirtualAddress==0x1000:
    off=0x39b5-0x1000;y[off:off+4]=x[off:off+4]
    off=0x3aed-0x1000;y[off:off+5]=x[off:off+5]
   self.assertEqual(x,y,a.Name)
  end=0x1000
  for section in P.sections:
   self.assertEqual(section.VirtualAddress,end);end=(end+max(section.Misc_VirtualSize,section.SizeOfRawData)+4095)//4096*4096
  self.assertEqual(end,P.OPTIONAL_HEADER.SizeOfImage);self.assertTrue(P.verify_checksum());self.assertFalse(P.get_warnings())
  self.assertEqual(len(P.DIRECTORY_ENTRY_IMPORT),len(old.DIRECTORY_ENTRY_IMPORT))
if __name__=='__main__':
 suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in [s.old.Tests,s.SeriesTests,GuardTests]])
 result=unittest.TextTestRunner(verbosity=2).run(suite);sys.exit(not result.wasSuccessful())
