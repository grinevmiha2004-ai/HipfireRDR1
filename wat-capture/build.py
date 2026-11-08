import sys,subprocess,struct,hashlib,json
from pathlib import Path
sys.path.insert(0,'/workspace/hipfire-reload/python-deps')
import pefile,capstone
R=Path(__file__).parent
flags=['g++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-fpie','-ffreestanding','-fno-exceptions','-fno-rtti','-fno-stack-protector','-fno-jump-tables','-fno-tree-switch-conversion','-fasynchronous-unwind-tables','-fno-shrink-wrap','-fno-shrink-wrap-separate','-mabi=ms','-mno-red-zone','-maccumulate-outgoing-args']
for cmd in [flags+['-c','capture.cpp','-o','capture.o'],['as','--64','bridge.S','-o','bridge.o'],['ld','-T','capture.ld','capture.o','bridge.o','-o','capture.elf']]:subprocess.run(cmd,cwd=R,check=True)
for sec,name in [('.text','code'),('.data','data')]:subprocess.run(['objcopy','-O','binary','--only-section='+sec,'capture.elf',name+'.bin'],cwd=R,check=True)
# No loader relocations or external data addresses are allowed in the extension.
assert 'R_X86_64' not in subprocess.check_output(['readelf','-r','capture.elf'],cwd=R,text=True)
syms={l.split()[3]:(int(l.split()[0],16),int(l.split()[1],16)) for l in subprocess.check_output(['nm','-S','--defined-only','capture.elf'],cwd=R,text=True).splitlines() if len(l.split())==4}
source=Path('/workspace/hipfire-series4/output/HipfireRDR1.red').read_bytes();assert hashlib.sha256(source).hexdigest()=='9c299b5aabd596712257b0841d2bc3d1c934713958822bbd1f2f5830c5818e77'
p=pefile.PE(data=source);b=bytearray(source);report=[]
def patch(rva,before,after,reason):
 assert len(before)==len(after);o=p.get_offset_from_rva(rva);assert bytes(b[o:o+len(before)])==before
 b[o:o+len(before)]=after;report.append({'rva':hex(rva),'before':before.hex(),'after':after.hex(),'reason':reason})
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
old=p.get_data(0x39b4,5);assert old[0]==0xe9
patch(0x39b4,old,b'\xe9'+struct.pack('<i',syms['capture_bridge'][0]-0x39b4-5),'observational F9 capture tick')
parent=next(e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress<=0x39b4<e.struct.EndAddress)
code=bytearray((R/'code.bin').read_bytes());code_rva=0x68000
entries=[];regs={'rbx':3,'rbp':5,'rsi':6,'rdi':7,'r12':12,'r13':13,'r14':14,'r15':15}
# Unwind info for every compiled function; no bridge or existing prologue is altered.
for name,(start,size) in syms.items():
 if not(code_rva<=start<code_rva+len((R/'code.bin').read_bytes())):continue
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
 bridge=name=='capture_bridge'
 code+=bytes([0x21 if bridge else 1,prolog,count,0])+blob
 if count%2:code+=b'\0\0'
 if bridge:code+=struct.pack('<III',parent.BeginAddress,parent.EndAddress,parent.UnwindData)
 entries.append((start,start+size,unwind))
while len(code)%4:code.append(0)
table=code_rva+len(code)
all_entries=sorted([(e.struct.BeginAddress,e.struct.EndAddress,e.struct.UnwindData) for e in p.DIRECTORY_ENTRY_EXCEPTION]+entries)
code+=b''.join(struct.pack('<III',*e) for e in all_entries)
data_rva=syms['state'][0];assert data_rva==(code_rva+len(code)+4095)//4096*4096,(hex(data_rva),len(code))
# .data contains only zero-initialized cache / -1 handles, never static pointers.
data=(R/'data.bin').read_bytes();assert len(data)<=64
align=lambda n,a:(n+a-1)//a*a
count=len(p.sections)
for name,rva,payload,flags in [(b'.watcap',code_rva,code,0x60000020),(b'.watdata',data_rva,data,0xc0000040)]:
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
print('Unwind:',len(entries),'SHA256:',hashlib.sha256(b).hexdigest())
