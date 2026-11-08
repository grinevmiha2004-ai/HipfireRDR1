import sys,struct,re,json
from pathlib import Path
sys.path.insert(0,'/workspace/hipfire-reload/python-deps');import pefile,capstone
r=Path(__file__).parent;o=pefile.PE('/workspace/hipfire-reload/RDR.exe',fast_load=True);g=pefile.PE(str(r/'friend-RDR.exe'),fast_load=True)
c=capstone.Cs(3,8);c.detail=True
mapping={}
def compare(a,b,n):
 x=list(c.disasm(o.get_data(a,n),a));y=list(c.disasm(g.get_data(b,n),b));assert len(x)==len(y)
 for i,j in zip(x,y):
  assert (i.address-a,i.size,i.mnemonic,len(i.operands))==(j.address-b,j.size,j.mnemonic,len(j.operands)),(i,j)
  for p,q in zip(i.operands,j.operands):
   assert p.type==q.type
   if p.type==capstone.x86.X86_OP_IMM and (i.mnemonic=='call' or i.mnemonic.startswith('j')):
    if a<=p.imm<=a+n:assert p.imm-a==q.imm-b
    elif p.imm!=q.imm:mapping[p.imm]=q.imm
   elif p.type==capstone.x86.X86_OP_MEM and p.mem.base==q.mem.base==capstone.x86.X86_REG_RIP:
    mapping[i.address+i.size+p.mem.disp]=j.address+j.size+q.mem.disp
   else:assert (p.reg,p.imm,p.mem.base,p.mem.index,p.mem.disp)==(q.reg,q.imm,q.mem.base,q.mem.index,q.mem.disp),(i.mnemonic,i.op_str,j.op_str)
 mapping[a]=b
compare(0xcdfa20,0xcdfe00,0xe7)
compare(0x5874c0,mapping[0x5874c0],0x11a)
data=g.get_memory_mapped_image();base=0x140000000
for match in re.finditer(re.escape(struct.pack('<Q',base+0x2192b0)),data):
 vt=match.start()-8
 get=lambda off:struct.unpack_from('<Q',data,vt+off)[0]-base
 count,children,create=get(0x58),get(0x60),get(0x88)
 if not(0<count<0x2000000 and 0<children<0x2000000 and 0<create<0x2000000):continue
 if g.get_data(count,5)!=o.get_data(0x585e60,5) or g.get_data(children,11)!=o.get_data(0x585e70,11):continue
 for oldvt,fn,n in [(0x1cbf468,0x588060,0x129),(0x1cbf520,0x588190,0x2d)]:
  if g.get_data(create,8)==o.get_data(fn,8):
   compare(fn,create,n);mapping[oldvt]=vt;mapping[0x585e60]=count;mapping[0x585e70]=children;mapping[0x219640]=0x2192b0
   print('vtable',hex(oldvt),'->',hex(vt),'create',hex(create))
assert all(k in mapping for k in [0x1cbf468,0x1cbf520,0x2ab5e78])
mapping[0xcdfa7a]=0xcdfe5a
(r/'wat-map.json').write_text(json.dumps({hex(a):hex(b) for a,b in sorted(mapping.items())},indent=2))
print((r/'wat-map.json').read_text())
