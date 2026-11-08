import sys,struct,json,hashlib
from pathlib import Path
sys.path.insert(0,'/workspace/hipfire-reload/python-deps')
import pefile,capstone
R=Path(__file__).parent
source=(R/'output/HipfireRDR1.red').read_bytes()
(R/'output/HipfireRDR1-unretargeted.red').write_bytes(source)
p=pefile.PE(data=source); b=bytearray(source)
g=pefile.PE(str(R/'friend-RDR.exe'),fast_load=True)
assert hashlib.sha256((R/'friend-RDR.exe').read_bytes()).hexdigest()=='cc27983d9b9183ad32bf9f12d234a3b76ced27d32cce054279895d65e765b2c5'
mp={0x22cbf00:0x22daf30,0x2c36778:0x2c45808,0x2c36768:0x2c457f8,0x2b159d8:0x2b24a58,0xca87f0:0xca8bd0,0xca8810:0xca8bf0,0x1d346f0:0x1d42af8,0x1c86278:0x1c94928,0x1c862d0:0x1c94980,0xd06020:0xd06400,0xd16020:0xd16400,0xd1da00:0xd1dde0,0x33d729:0x33d399,0x34d729:0x34d399,0x103ffff:0x104bfff}
mp.update({-k:-v for k,v in list(mp.items())})
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
report=[];seen=set();counts={x:0 for x in mp}
def patch(rva,old,new,reason):
 off=p.get_offset_from_rva(rva);assert bytes(b[off:off+len(old)])==old,(hex(rva),reason)
 b[off:off+len(old)]=new;report.append({'rva':hex(rva),'before':old.hex(),'after':new.hex(),'reason':reason})
# Disassemble actual runtime function ranges; also include leaf code not in .pdata.
ranges=[(e.struct.BeginAddress,e.struct.EndAddress) for e in p.DIRECTORY_ENTRY_EXCEPTION]
ranges += [(0x1000,0x7400),(0xcd50,0xe6a0),(0x62000,0x62800),(0x65000,0x65b00)]
for start,end in ranges:
 for i in cs.disasm(p.get_data(start,end-start),start):
  if i.address in seen:continue
  seen.add(i.address)
  for op in i.operands:
   value=None
   if op.type==capstone.x86.X86_OP_IMM:value=op.imm;offset=i.imm_offset;size=i.imm_size
   elif op.type==capstone.x86.X86_OP_MEM and op.mem.base!=capstone.x86.X86_REG_RIP:value=op.mem.disp;offset=i.disp_offset;size=i.disp_size
   if value in mp:
    assert size in [4,8]
    patch(i.address+offset,value.to_bytes(size,'little',signed=value<0),mp[value].to_bytes(size,'little',signed=mp[value]<0),i.mnemonic+' '+i.op_str)
    counts[value]+=1
assert all(counts[k] for k in counts if k>0),counts
# Caller allowlists for real input queries, same semantics at their new locations.
for rva,values in [(0x20df0,[0x305838,0x34847a,0x349093,0x349a7a]),(0x20e00,[0x374435,0x37446b,0x3744d0,0x3744eb,0x374738,0x374751])]:
 for j,v in enumerate(values):patch(rva+j*4,struct.pack('<I',v),struct.pack('<I',v-0x390),'input caller allowlist')
# Draw activity guard includes a RIP-relative operand whose encoding has changed.
old=pefile.PE('/workspace/hipfire-reload/RDR.exe',fast_load=True)
assert old.get_data(0x34d729,8)==g.get_data(0x34d399,8)
patch(0xcebb,old.get_data(0x34d729+8,8),g.get_data(0x34d399+8,8),'draw activity signature')
for a,n,length in [(0xd16020,0xd16400,24),(0xd1da00,0xd1dde0,33),(0xca87f0,0xca8bd0,32)]:assert old.get_data(a,length)==g.get_data(n,length)
for vtable,fn in [(0x1c94980,0x3d9dd0),(0x1d42af8,0xca8bd0)]:assert struct.unpack('<Q',g.get_data(vtable,8))[0]==0x140000000+fn
q=pefile.PE(data=b);struct.pack_into('<I',b,p.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),q.generate_checksum())
(R/'output').mkdir(exist_ok=True);(R/'output/HipfireRDR1.red').write_bytes(b)
(R/'compat-report.json').write_text(json.dumps(report,indent=2))
prior=json.loads((R/'patch-report.json').read_text());(R/'patch-report.json').write_text(json.dumps(prior+report,indent=2))
print('Patches:',len(report),'references:',{hex(k):v for k,v in counts.items()})
print('SHA256:',hashlib.sha256(b).hexdigest())
