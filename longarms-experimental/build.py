import sys,subprocess,struct,hashlib,json
from pathlib import Path
sys.path.insert(0,'/workspace/hipfire-reload/python-deps')
import pefile,capstone
R=Path(__file__).parent
flags=['g++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-fpie','-ffreestanding','-fno-exceptions','-fno-rtti','-fno-stack-protector','-fno-jump-tables','-fno-tree-switch-conversion','-fasynchronous-unwind-tables','-fno-shrink-wrap','-fno-shrink-wrap-separate','-mabi=ms','-mno-red-zone','-maccumulate-outgoing-args']
for cmd in [flags+['-c','longarms.cpp','-o','longarms.o'],['as','--64','select.S','-o','select.o'],['as','--64','tick.S','-o','tick.o'],['ld','-T','longarms.ld','longarms.o','select.o','tick.o','-o','longarms.elf']]:subprocess.run(cmd,cwd=R,check=True)
for sec,name in [('.text','code'),('.data','data')]:subprocess.run(['objcopy','-O','binary','--only-section='+sec,'longarms.elf',name+'.bin'],cwd=R,check=True)
# No loader relocations or external data addresses are allowed in the extension.
assert 'R_X86_64' not in subprocess.check_output(['readelf','-r','longarms.elf'],cwd=R,text=True)
syms={l.split()[3]:(int(l.split()[0],16),int(l.split()[1],16)) for l in subprocess.check_output(['nm','-S','--defined-only','longarms.elf'],cwd=R,text=True).splitlines() if len(l.split())==4}
source=Path('/workspace/hipfire-series4/output/HipfireRDR1.red').read_bytes();assert hashlib.sha256(source).hexdigest()=='9c299b5aabd596712257b0841d2bc3d1c934713958822bbd1f2f5830c5818e77'
p=pefile.PE(data=source);b=bytearray(source);report=[]
def patch(rva,before,after,reason):
 assert len(before)==len(after);o=p.get_offset_from_rva(rva);assert bytes(b[o:o+len(before)])==before
 b[o:o+len(before)]=after;report.append({'rva':hex(rva),'before':before.hex(),'after':after.hex(),'reason':reason})
# SDK firearm IDs 0..20; lasso/melee/throwables/turrets remain excluded.
for rva in [0x3a71,0x404b,0x4a6f]:patch(rva,b'\x07',b'\x14','weapon limit 7 -> 20')
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
redirect={0xd730:'select_node',0xd7f0:'playing_node',0xda70:'rapid_pose',0x15c0:'longarm_aim',0x620f0:'mark_empty_stable'};seen=set();counts={k:0 for k in redirect}
for e in p.DIRECTORY_ENTRY_EXCEPTION:
 start=e.struct.BeginAddress;end=e.struct.EndAddress
 for i in cs.disasm(p.get_data(start,end-start),start):
  if i.address in seen:continue
  seen.add(i.address)
  if i.mnemonic in ['call','jmp'] and i.operands[0].type==capstone.x86.X86_OP_IMM and i.operands[0].imm in redirect:
   dest=i.operands[0].imm;assert i.size==5 and i.imm_size==4
   patch(i.address+1,i.bytes[1:],struct.pack('<i',syms[redirect[dest]][0]-i.address-5),redirect[dest]);counts[dest]+=1
assert all(counts.values())
# Reuse the existing early control-passthrough branch. Only these two
# calls are policy-specific; the rest of cover handling remains unchanged.
for call,old_target,name in [(0x4024,0xd8f0,'should_passthrough'),(0x4762,0x1f80,'cancel_passthrough')]:
 old=p.get_data(call,5);assert old[0]==0xe8 and call+5+struct.unpack('<i',old[1:])[0]==old_target
 patch(call+1,old[1:],struct.pack('<i',syms[name][0]-call-5),name)
old=p.get_data(0x39b4,5);assert old[0]==0xe9 and 0x39b9+struct.unpack('<i',old[1:])[0]==0x655ae
patch(0x39b4,old,b'\xe9'+struct.pack('<i',syms['longarm_bridge'][0]-0x39b4-5),'bounded longarm timing tick')
parent=next(e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress<=0x39b4<e.struct.EndAddress)
code=bytearray((R/'code.bin').read_bytes());code_rva=0x68000
function_names={l.split()[3] for l in subprocess.check_output(['nm','-S','--defined-only','longarms.elf'],cwd=R,text=True).splitlines() if len(l.split())==4 and l.split()[2].lower()=='t'}
entries=[];regs={'rbx':3,'rbp':5,'rsi':6,'rdi':7,'r12':12,'r13':13,'r14':14,'r15':15}
# Unwind info for every compiled function; no bridge or existing prologue is altered.
for name,(start,size) in syms.items():
 if name not in function_names or not(code_rva<=start<code_rva+len((R/'code.bin').read_bytes())):continue
 ops=[];prolog=0
 for i in cs.disasm(bytes(code[start-code_rva:start-code_rva+80]),start):
  off=i.address+i.size-start
  if i.mnemonic=='pushfq' or (i.mnemonic=='push' and i.op_str not in regs):ops.append(bytes([off,2]));prolog=off
  elif i.mnemonic=='push' and i.op_str in regs:ops.append(bytes([off,regs[i.op_str]<<4]));prolog=off
  elif i.mnemonic=='sub' and i.op_str.startswith('rsp, '):
   n=int(i.op_str.split(', ')[1],0);ops.append(bytes([off,((n//8-1)<<4)|2]) if n<=128 else bytes([off,1])+struct.pack('<H',n//8));prolog=off;break
  elif i.mnemonic in ['mov','xor','lea','test','cmp','nop']:continue
  else:break
 while len(code)%4:code.append(0)
 unwind=code_rva+len(code);blob=b''.join(reversed(ops));count=len(blob)//2
 bridge=name=='longarm_bridge'
 code+=bytes([0x21 if bridge else 1,prolog,count,0])+blob
 if count%2:code+=b'\0\0'
 if bridge:code+=struct.pack('<III',parent.BeginAddress,parent.EndAddress,parent.UnwindData)
 entries.append((start,start+size,unwind))
while len(code)%4:code.append(0)
table=code_rva+len(code)
all_entries=sorted([(e.struct.BeginAddress,e.struct.EndAddress,e.struct.UnwindData) for e in p.DIRECTORY_ENTRY_EXCEPTION]+entries)
code+=b''.join(struct.pack('<III',*e) for e in all_entries)
data_rva=syms['choice'][0];assert len(code)<=data_rva-code_rva;code+=b'\0'*(data_rva-code_rva-len(code))
# .data contains only zero-initialized cache / -1 handles, never static pointers.
data=(R/'data.bin').read_bytes();assert len(data)<=256
align=lambda n,a:(n+a-1)//a*a
count=len(p.sections)
for name,rva,payload,flags in [(b'.longarm',code_rva,code,0x60000020),(b'.lngdata',data_rva,data,0xc0000040)]:
 raw=align(len(b),512);size=align(len(payload),512);b+=b'\0'*(raw-len(b))+payload+b'\0'*(size-len(payload))
 h=p.sections[0].get_file_offset()+count*40;assert h+40<=p.OPTIONAL_HEADER.SizeOfHeaders and not any(b[h:h+40])
 b[h:h+40]=struct.pack('<8sIIIIIIHHI',name,len(payload),rva,size,raw,0,0,0,0,flags);count+=1
 field='SizeOfCode' if flags&0x20 else 'SizeOfInitializedData';struct.pack_into('<I',b,p.OPTIONAL_HEADER.get_field_absolute_offset(field),getattr(p.OPTIONAL_HEADER,field)+size)
struct.pack_into('<H',b,p.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),count)
struct.pack_into('<I',b,p.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),align(data_rva+len(data),4096))
struct.pack_into('<II',b,p.OPTIONAL_HEADER.DATA_DIRECTORY[3].get_file_offset(),table,len(all_entries)*12)
q=pefile.PE(data=b);struct.pack_into('<I',b,p.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),q.generate_checksum())
(R/'output').mkdir(exist_ok=True);(R/'output/HipfireRDR1.red').write_bytes(b)
(R/'patch-report.json').write_text(json.dumps(report,indent=2));(R/'symbols.json').write_text(json.dumps(syms,indent=2))
print('Calls:',counts,'Unwind:',len(entries),'SHA256:',hashlib.sha256(b).hexdigest())
