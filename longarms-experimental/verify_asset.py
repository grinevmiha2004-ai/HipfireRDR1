"""Validate the selected authored graph against a locally unpacked WAT; publish only the profile."""
import sys,struct,hashlib,json
from pathlib import Path
b=Path(sys.argv[1]).read_bytes()
def u(p):return struct.unpack_from('<I',b,p)[0]
def ptr(p):
 v=u(p);assert v>>28==5;return v&0xfffffff
def kids(n):
 count=u(n+12)&65535
 return [ptr(ptr(n+8)+4*i) for i in range(count)] if count else []
def hashes(n):return [u(c+32) for c in kids(n)]
def path(n):
 out=[]
 while n:
  out.insert(0,f'{u(n+32):08x}');p=u(n+4);n=p&0xfffffff if p>>28==5 else 0
 return out
family=0x171800
assert path(family)==['bd701184','18e67533','840a9c18','bcacd642','afd53e15']
assert hashes(family)==[0x61d07327,0x56bc16f8,0x7e84a609]
entries=[]
for n,mode,prefix in [(0x171900,'stand','nor_rfl_stn_rpd_'),(0x171980,'walk','nor_rfl_wlk_rpd_'),(0x1719c0,'run','nor_rfl_run_rpd_')]:
 tracks=[ptr(ptr(n+44)+i*4) for i in range(u(n+48)&65535)]
 aim=[t for t in tracks if u(t)==0x17];assert len(aim)==1
 clips=[b[ptr(aim[0]+i):].split(b'\0',1)[0].decode('ascii') for i in range(16,32,4)]
 assert all(c.startswith(prefix) for c in clips[:3]);assert clips[3].endswith('_fir')
 entries.append(dict(mode=mode,path=path(n),clips=clips))
# The crouched rifle subtree has ordinary aim/fire clips, no rapid family.
root=0x100300
seen=set();crouch_clips=set();node_hashes=set()
def visit(n):
 if n in seen:return
 seen.add(n);node_hashes.add(u(n+32))
 for child in kids(n):visit(child)
 count=u(n+48)&65535
 for i in range(count):
  t=ptr(ptr(n+44)+4*i)
  if u(t)==0 and u(t+16)>>28==5:visit(ptr(t+16))
  elif u(t)==23:
   for k in range(16,32,4):
    if u(t+k)>>28==5:crouch_clips.add(b[ptr(t+k):].split(b'\0',1)[0].decode('ascii'))
visit(root)
assert len(seen)==26 and 0xbcacd642 not in node_hashes
assert len(crouch_clips)==18 and not any('_rpd_' in clip for clip in crouch_clips)
print(json.dumps(dict(source='act.rpf/default_character.wat',unpacked_sha256=hashlib.sha256(b).hexdigest(),family_path=path(family),child_hashes=[f'{v:08x}' for v in hashes(family)],actions=entries,crouch=dict(path=path(root),nodes=len(seen),ordinary_clips=sorted(crouch_clips),dedicated_rapid_family=False)),indent=2))
