using U=unsigned;using Q=unsigned long long;using B=unsigned char;
#define MS __attribute__((ms_abi))
extern "C" {
int MS original_select(int,const char*);int MS original_playing(int,const char*);
int MS original_weapon(int);bool MS original_rapid(U,bool,bool);
Q MS actor_from(Q,U);Q MS read_pointer(Q);
extern Q game_image,iat_rpm;
void MS log_event(const char*,...);
bool MS select_resolved(Q,Q);
}
using RPM=int(MS*)(void*,const void*,void*,Q,Q*);
static bool read(Q p,void* out,Q n){Q got=0;return p>=0x10000&&p<0x0000800000000000ULL-n&&reinterpret_cast<RPM>(iat_rpm)(reinterpret_cast<void*>(-1LL),reinterpret_cast<const void*>(p),out,n,&got)&&got==n;}
template<class T>T value(Q p){T result{};read(p,&result,sizeof(result));return result;}
static Q ptr(Q p){return value<Q>(p);}
static bool eq(const char* a,const char* b){if(!a||!b)return false;while(*a&&*a==*b){++a;++b;}return *a==*b;}
static bool rifle(int w){return w>=8&&w<=20&&w!=15;} // Capture: sawed-off uses Pistol/DeadEye.
struct Choice {int actor=-1,weapon=-1;Q nodes[4]{};U refused=0;};
Choice choice;
static int weapon(int actor){
 int w=original_weapon(actor);
 if(w>=0){if(choice.actor!=actor||choice.weapon!=w){choice.actor=actor;choice.weapon=w;for(auto& p:choice.nodes)p=0;choice.refused=0;}return w;}
 return w==-1&&choice.actor==actor?choice.weapon:-1;
}
static int kind(const char* path){
 if(eq(path,"default_character_Main\\Gunplay\\Pistol\\DeadEye\\PistolHoldStand"))return 0;
 if(eq(path,"default_character_Main\\tcwtnjb\\Pistol\\PistolAim\\DeadEye\\PistolHoldRun"))return 1;
 if(eq(path,"default_character_Main\\l8x7gpa\\Crouch\\t175e2a\\CrouchPistol\\PistolAim\\DeadEye\\PistolHoldStand"))return 2;
 if(eq(path,"default_character_Main\\l8x7gpa\\Crouch\\t175e2a\\CrouchPistol\\PistolAim\\DeadEye\\PistolHoldRun"))return 3;
 return -1;
}
struct Node {Q vt,parent,children;unsigned short count,capacity;U unknown;Q type,flags,name;U hash,tail;};
static_assert(sizeof(Node)==64);
static bool node(Q p,Node& out){
 if(!read(p,&out,sizeof(out))||out.vt<game_image+0x1040000||out.vt>=game_image+0x2000000||out.count>2048||out.count>out.capacity)return false;
 // Layout and these three inherited pure getters were recorded in the
 // user's loaded WAT. Read the objects; do not invoke virtual getters.
 return ptr(out.vt+8)==game_image+0x219640&&ptr(out.vt+0x58)==game_image+0x585e60&&ptr(out.vt+0x60)==game_image+0x585e70;
}
static Q child(Q p,U hash){
 Node n{};if(!node(p,n))return 0;
 for(U i=0;i<n.count;++i){Q c=ptr(n.children+i*8ULL);Node x{};if(node(c,x)&&x.parent==p&&x.hash==hash)return c;}
 return 0;
}
static Q find(Q p,Q parent,U hash,bool deadeye,U depth,U& budget,Q& found,U& matches){
 if(!budget||depth>20)return 0;
 --budget;Node n{};if(!node(p,n)||n.parent!=parent)return 0;
 deadeye=deadeye||n.hash==0xbcacd642U||n.hash==0x122ac9f4U; // RifleDeadEye / DeadEye
 if(n.hash==hash&&deadeye){found=p;++matches;return p;}
 for(U i=0;i<n.count&&budget&&matches<2;++i)find(ptr(n.children+i*8ULL),p,hash,deadeye,depth+1,budget,found,matches);
 return found;
}
struct ResolveInfo {U stage=0,root_hash=0,matches=0;};
static Q resolve(U k,Q owner,ResolveInfo& info){
 Q base=ptr(game_image+0x2ab5e78);Node root{};
 // Native lookup at 5874C0 skips the initial path component and starts
 // at the current tree namespace, normally default_character_Main itself.
 // Experimental 02 incorrectly required this pointer to name Global.
 if(node(base,root)){
  info.root_hash=root.hash;
  if(root.hash==0xdb982272U)base=child(base,0xbd701184U);
  else if(root.hash!=0xbd701184U)base=0;
 }else base=0;
 if(!base){
  // The captured local actor chain provides another verified route to
  // its own tree root when the global namespace is temporarily unavailable.
  Q controller=ptr(owner+0xb0),current=controller?ptr(controller+0xb0):0;
  for(U depth=0;current&&depth<24;++depth){
   Node n{};if(!node(current,n))break;
   if(n.hash==0xbd701184U){base=current;info.root_hash=n.hash;break;}
   if(n.parent==current)break;
   current=n.parent;
  }
 }
 if(!base){info.stage=1;return 0;}
 if(k==0){
  // Exact chain captured during the native Winchester Dead Eye shot.
  Q target=child(child(child(child(child(base,0x18e67533U),0x840a9c18U),0xbcacd642U),0xafd53e15U),0x61d07327U);
  info.stage=target?0:2;info.matches=target?1:0;return target;
 }
 Q scope=k==1?child(base,0xf6ad55f0U):child(child(base,0x892a3c35U),0x2751a740U);
 if(!scope){info.stage=3;return 0;}
 Node scope_node{};if(!node(scope,scope_node)){info.stage=4;return 0;}
 U budget=4096,matches=0;Q found=0;
 find(scope,scope_node.parent,(k&1)?0x7e84a609U:0x61d07327U,false,0,budget,found,matches);
 info.matches=matches;
 if(matches!=1||!budget){info.stage=5;return 0;}
 return found;
}
static bool signature(){
 // Build-specific bodies used by the native action-node selector, and
 // read-only methods which establish the WAT object layout.
 extern const B selector_signature[];extern const U selector_size;
 const B prologue[]={0x40,0x57,0x48,0x81,0xec,0x70,0x01,0,0};B pro[9]{};
 if(!read(game_image+0xcdfa20,pro,9))return false;
 for(U i=0;i<9;++i)if(pro[i]!=prologue[i])return false;
 B code[160]{};if(selector_size>sizeof(code)||!read(game_image+0xcdfa7a,code,selector_size))return false;
 for(U i=0;i<selector_size;++i)if(code[i]!=selector_signature[i])return false;
 const B getter[]={0x48,0x8d,0x41,0x30,0xc3};B a[5]{};
 if(!read(game_image+0x219640,a,5))return false;
 for(U i=0;i<5;++i)if(a[i]!=getter[i])return false;
 const B count[]={0x0f,0xb7,0x41,0x18,0xc3};
 if(!read(game_image+0x585e60,a,5))return false;
 for(U i=0;i<5;++i)if(a[i]!=count[i])return false;
 const B children[]={0x48,0x8b,0x41,0x10,0x8b,0xd2,0x48,0x8b,0x04,0xd0,0xc3};B c[11]{};
 if(!read(game_image+0x585e70,c,11))return false;
 for(U i=0;i<11;++i)if(c[i]!=children[i])return false;
 return true;
}
static Q owner_for(int actor){
 Q owner=actor_from(game_image,static_cast<U>(actor));Q character=owner?ptr(owner+0x38):0;
 Q player=ptr(game_image+0x22cbf00);
 if(!owner||!character||!player||ptr(character+0x10)!=owner||value<U>(owner+8)!=value<U>(player+0x5ec))return 0;
 return owner;
}
extern "C" int MS select_node(int actor,const char* path){
 int k=kind(path);if(k<0)return original_select(actor,path);
 int w=weapon(actor);
 if(!rifle(w)){int result=original_select(actor,path);if(w==15&&result)log_event("longarm_route actor=%d weapon=15 kind=%d family=pistol",actor,k);return result;}
 if(!signature()){log_event("longarm_resolve refused: executable signature mismatch");return 0;}
 Q owner=owner_for(actor),controller=owner?ptr(owner+0xb0):0;
 if(!owner||!controller)return 0;
 // Resolve against the current tree on each pose selection: no stale
 // pointers across tree unloads or actor changes, no guessed path strings.
 ResolveInfo info{};Q target=resolve(static_cast<U>(k),owner,info);Node n{};
 if(!target||!node(target,n)){
  if(!(choice.refused&(1U<<k))){choice.refused|=1U<<k;log_event("longarm_resolve unavailable actor=%d weapon=%d kind=%d stage=%u root_hash=%08x matches=%u",actor,w,k,info.stage,info.root_hash,info.matches);}
  choice.nodes[k]=0;return 0;
 }
 // Native selector reads this slot and invokes +0x88 on the resolved node.
 Q create=ptr(n.vt+0x88);
 if(!((n.vt==game_image+0x1cbf468&&create==game_image+0x588060)||(n.vt==game_image+0x1cbf520&&create==game_image+0x588190)))return 0;
 if(!select_resolved(owner,target)){choice.nodes[k]=0;return 0;}
 choice.nodes[k]=target;
 log_event("longarm_resolve ready actor=%d weapon=%d kind=%d node_hash=%08x",actor,w,k,n.hash);return 1;
}
static bool active(int actor,U k){
 Q expected=choice.nodes[k];if(!expected)return false;
 Node target{};if(!node(expected,target))return false;
 Q owner=owner_for(actor),controller=owner?ptr(owner+0xb0):0;
 Q current=controller?ptr(controller+0xb0):0;
 for(U depth=0;current&&depth<24;++depth){
  Node x{};if(!node(current,x))return false;
  if(current==expected)return true;
  if(x.parent==current)return false;
  current=x.parent;
 }
 return false;
}
extern "C" int MS playing_node(int actor,const char* path){
 int k=kind(path);if(k<0)return original_playing(actor,path);
 return rifle(weapon(actor))?active(actor,static_cast<U>(k)):original_playing(actor,path);
}
extern "C" bool MS rapid_pose(U actor,bool moving,bool crouched){
 if(!rifle(weapon(static_cast<int>(actor))))return original_rapid(actor,moving,crouched);
 return active(static_cast<int>(actor),(moving?1U:0U)+(crouched?2U:0U));
}
#include "signature.hpp"
