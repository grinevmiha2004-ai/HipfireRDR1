from pathlib import Path
import json,re
r=Path(__file__).parent
mp={int(a,16):int(b,16) for a,b in json.loads((r/'combined-map.json').read_text()).items()}
mp.update({0x208390:0x208000,0x3015d0:0x301240,0x1d62460:0x1d70b68,0x2c366c8:0x2c45770})
def adapt(s):return re.sub(r'0x[0-9a-fA-F]+',lambda m:hex(mp.get(int(m[0],16),int(m[0],16))),s)
s=adapt(Path('/workspace/hipfire-reload/test_reload.py').read_text())
s=s.replace("str(ROOT/'RDR.exe')","str(ROOT/'friend-RDR.exe')").replace("str(ROOT/'extension.elf')","'/workspace/hipfire-reload/extension.elf'")
(r/'test_reload_friend.py').write_text(s)
s=adapt(Path('/workspace/hipfire-series/test_series.py').read_text()).replace('/workspace/hipfire-reload/test_reload.py',str(r/'test_reload_friend.py'));(r/'test_series_friend.py').write_text(s)
s=adapt(Path('/workspace/hipfire-series4/test_rapid.py').read_text()).replace('/workspace/hipfire-series/test_series.py',str(r/'test_series_friend.py'));(r/'test_rapid_friend.py').write_text(s)
s=adapt(Path('/workspace/hipfire-longarms11/test_longarms.py').read_text()).replace('/workspace/hipfire-series4/test_rapid.py',str(r/'test_rapid_friend.py')).replace('/workspace/hipfire-reload/RDR.exe',str(r/'friend-RDR.exe'))
# Historical user-profile binaries are tested upstream; they cannot run
# against this different EXE's native addresses. Retain all current tests.
exclude={'test_reproduced_goal_replacement_is_repaired_only_after_initial_aim','test_longarm_standing_backlog_from_07_expires_in_08','test_first_crouch_raise_survives_logged_queued_delay_but_has_fixed_startup_bound','test_reproduced_09_crouch_for_aim_handoff_no_longer_blocks_shoot_goal'}
s=s.replace('(LongarmTests,set())',f'(LongarmTests,{exclude!r})')
extra=Path('/workspace/hipfire-compat/test_compat.py').read_text()
extra=extra[extra.index('class CompatTests('):extra.index('# Skip historical')]
extra='o=m.s.old\n'+extra
s=s.replace('suite=unittest.TestSuite()',extra+'\nsuite=unittest.TestSuite()')
s=s.replace("r=unittest.TextTestRunner(verbosity=2).run(suite)","for name in ['test_real_file_identity_accepts_friend_getter_rejects_modified_code','test_input_new_keyboard_and_locomotion_callers','test_input_aim_other_actors_old_callers_and_deadeye_passthrough','test_missing_locomotion_hook_refuses_start']:suite.addTest(CompatTests(name))\nr=unittest.TextTestRunner(verbosity=2).run(suite)")
pos=s.index(' def test_final_pe_and_original_sections')
s=s[:pos]+''' def test_friend_crouch_startup_is_fixed_and_bounded_without_old_profile_binary(self):
  v=self.crouch_startup_expiry_trial();self.assertEqual(v.u.mem_read(v.frame+0x770,1),b'\\1')
  v.q(v.frame+0x40,1787);self.call(v,'longarm_controls',v.frame);self.assertEqual(v.u.mem_read(v.frame+0x770,1),b'\\1')
  v.q(v.frame+0x40,1788);self.call(v,'longarm_controls',v.frame);self.assertEqual(v.u.mem_read(v.frame+0x770,1),b'\\0')
 def test_friend_profile_preserves_upstream_11_cpp_logic(self):
  import re
  norm=lambda x:re.sub(r'0x[0-9a-fA-F]+','HEX',x)
  self.assertEqual(norm((R/'longarms.cpp').read_text()),norm(Path('/workspace/hipfire-longarms11/longarms.cpp').read_text()))
'''+s[pos:]
(r/'test_longarms.py').write_text(s)
