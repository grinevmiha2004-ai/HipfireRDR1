using Q=unsigned long long;using U=unsigned;using B=unsigned char;
#define MS __attribute__((ms_abi))
extern "C" {extern Q game_image,iat_rpm,iat_time,iat_key,rh_init,rh_push,rh_call;void MS log_event(const char*,...);}
using RPM=int(MS*)(void*,const void*,void*,Q,Q*);
static bool read(Q p,void* out,Q n){Q got=0;return p>=0x10000&&p<0x0000800000000000ULL-n&&reinterpret_cast<RPM>(iat_rpm)(reinterpret_cast<void*>(-1LL),reinterpret_cast<void*>(p),out,n,&got)&&got==n;}
template<class T>T value(Q p){T result{};read(p,&result,sizeof(result));return result;}
static Q ptr(Q p){return value<Q>(p);}
struct State {Q until=0,next=0,last_node=0;U last_exec=0xffffffffU,last_weapon=0xffffffffU;B key=0,stop=0;};
State state;
static bool code(Q p){return p>=game_image+0x1000&&p<game_image+0x1040000;}
static Q name_header(Q node,Q getter){
 for(U hop=0;hop<3;++hop){
  B c[16]{};if(!code(getter)||!read(getter,c,sizeof(c)))return 0;
  // Decode pure accessors only. No game virtual method is invoked.
  if(c[0]==0xe9){int d=0;if(!read(getter+1,&d,4))return 0;getter=getter+5+static_cast<long long>(d);continue;}
  if(c[0]==0x48&&c[1]==0x8d&&c[2]==0x41&&c[4]==0xc3)return node+static_cast<signed char>(c[3]);
  if(c[0]==0x48&&c[1]==0x8d&&c[2]==0x81&&c[7]==0xc3){int d=0;if(!read(getter+3,&d,4)||d<0||d>1024)return 0;return node+static_cast<U>(d);}
  if(c[0]==0x48&&c[1]==0x8b&&c[2]==0xc1&&c[3]==0xc3)return node;
  return 0;
 }
 return 0;
}
extern "C" Q MS decode_name(Q node,Q getter){return name_header(node,getter);}
static void node_name(U depth,Q header){
 if(!header)return;
 Q source=ptr(header);char name[96]{};bool good=false;
 for(U j=0;j<sizeof(name)-1;++j){B c=0;if(!read(source+j,&c,1))break;if(!c){good=j>0;break;}if(c<32||c>126)break;name[j]=static_cast<char>(c);}
 if(good)log_event("wat_name depth=%u name=%s",depth,name);
}
static Q pool(Q address,U handle){
 if(handle==0xffffffffU||!address)return 0;
 Q entry=address+static_cast<Q>(handle&0xffffU)*16;unsigned short gen=0;
 return read(entry+8,&gen,2)&&gen==(handle>>16)?ptr(entry):0;
}
static int native(U hash,int arg,bool push){
 reinterpret_cast<void(MS*)(U)>(rh_init)(hash);
 if(push)reinterpret_cast<void(MS*)(Q)>(rh_push)(static_cast<U>(arg));
 const Q* result=reinterpret_cast<const Q*(MS*)()>(rh_call)();return result?static_cast<int>(*result):-1;
}
extern "C" void MS capture_tick(B*){
 Q now=reinterpret_cast<Q(MS*)()>(iat_time)();
 const bool key=(reinterpret_cast<short(MS*)(int)>(iat_key)(0x78)&0x8000)!=0;
 const bool stop=(reinterpret_cast<short(MS*)(int)>(iat_key)(0x7a)&0x8000)!=0;
 if(key&&!state.key){state.until=now+60000;state.next=0;state.last_node=0;state.last_exec=0xffffffffU;state.last_weapon=0xffffffffU;log_event("wat_capture begin duration_ms=60000 readonly=1");}
 state.key=key;
 if(stop&&!state.stop){state.until=0;log_event("wat_capture stopped");}state.stop=stop;
 if(!state.until)return;
 if(now>=state.until){state.until=0;log_event("wat_capture timeout");return;}
 if(now<state.next)return;
 state.next=now+50;
 Q player=ptr(game_image+0x22cbf00);if(!player)return;
 U raw_handle=value<U>(player+0x5ec);
 Q owner=pool(ptr(game_image+0x2c36768),raw_handle);
 Q controller=owner?ptr(owner+0xb0):0,node=controller?ptr(controller+0xb0):0;
 Q de=player?ptr(player+0x410):0;U exec=value<U>(de+0x20),mode=value<U>(de+0x1c);
 const int p=native(0xad68a22e,0,false),actor=p>=0?native(0xe8cfdd53,p,true):-1;
 U weapon=actor>=0?static_cast<U>(native(0xa4b2016d,actor,true)):0xffffffffU;
 if(node==state.last_node&&exec==state.last_exec&&weapon==state.last_weapon)return;
 state.last_node=node;state.last_exec=exec;state.last_weapon=weapon;
 log_event("wat_capture sample actor=%d weapon=%d de_mode=%u de_exec=%u node=%llx",actor,static_cast<int>(weapon),mode,exec,node);
 Q visited[24]{};
 for(U depth=0;node&&depth<24;++depth){
  for(U j=0;j<depth;++j)if(visited[j]==node){log_event("wat_capture cycle depth=%u",depth);return;}
  visited[depth]=node;
  Q vt=ptr(node);if(vt<game_image+0x1040000||vt>=game_image+0x2000000){log_event("wat_capture invalid_vtable depth=%u",depth);break;}
  Q getter=ptr(vt+8),header=name_header(node,getter);U hash=value<U>(header+8);
  Q parent=ptr(node+8);B bytes[16]{};read(getter,bytes,sizeof(bytes));
  Q a=0,b=0;for(U j=0;j<8;++j){a|=static_cast<Q>(bytes[j])<<(j*8);b|=static_cast<Q>(bytes[j+8])<<(j*8);}
  log_event("wat_node depth=%u node=%llx parent=%llx vt_rva=%llx getter_rva=%llx header=%llx hash=%08x code=%016llx%016llx",depth,node,parent,vt-game_image,getter-game_image,header,hash,a,b);
  node_name(depth,header);
  const U method_slots[]={0x58,0x60};
  for(U slot:method_slots){Q fn=ptr(vt+slot),bytes[4]{};if(code(fn)&&read(fn,bytes,sizeof(bytes)))log_event("wat_method depth=%u slot=%x rva=%llx code=%016llx %016llx %016llx %016llx",depth,slot,fn-game_image,bytes[0],bytes[1],bytes[2],bytes[3]);}
  // Fixed-size game object metadata only, useful if a name accessor is unknown.
  Q raw[8]{};if(read(node,raw,sizeof(raw)))log_event("wat_raw depth=%u data=%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx",depth,raw[0],raw[1],raw[2],raw[3],raw[4],raw[5],raw[6],raw[7]);
  Q tail[8]{};if(read(node+64,tail,sizeof(tail)))log_event("wat_tail depth=%u data=%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx",depth,tail[0],tail[1],tail[2],tail[3],tail[4],tail[5],tail[6],tail[7]);
  node=parent;
 }
}
