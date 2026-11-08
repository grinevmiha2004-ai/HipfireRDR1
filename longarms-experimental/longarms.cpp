using U=unsigned;using Q=unsigned long long;using B=unsigned char;
#define MS __attribute__((ms_abi))
extern "C" {
int MS original_select(int,const char*);int MS original_playing(int,const char*);
int MS original_weapon(int);int MS original_pose(int);int MS original_cover(int);
void MS original_cancel(void*,const char*,bool);
extern int owned_actor,owned_kind;extern B owned_expanded,owned_goal,input_enabled,mod_enabled;extern Q release_at;
void MS original_aim(int,void*);bool MS original_rapid(U,bool,bool);
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
struct Choice {int actor=-1,weapon=-1;Q nodes[4]{};U refused=0;B crouch_passthrough=0,after_goal=0;Q prepare_value=0,confirmation=0,hold_until=0;};
Choice choice;
static int weapon(int actor){
 int w=original_weapon(actor);
 if(w>=0){if(choice.actor!=actor||choice.weapon!=w){choice.actor=actor;choice.weapon=w;for(auto& p:choice.nodes)p=0;choice.refused=0;choice.after_goal=0;choice.prepare_value=choice.confirmation=choice.hold_until=0;}return w;}
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
 if(k<2){
  // act.rpf/default_character.wat: this composite owns the standing,
  // walking (56BC16F8) and running (7E84A609) rapid-fire actions.
  // In locomotion let the authored child conditions select the action;
  // forcing RifleHoldStand bypassed those conditions and never fired.
  Q family=child(child(child(child(base,0x18e67533U),0x840a9c18U),0xbcacd642U),0xafd53e15U);
  Q target=k==0?child(family,0x61d07327U):family;
  if(k==1&&(!child(family,0x61d07327U)||!child(family,0x56bc16f8U)||!child(family,0x7e84a609U)))target=0;
  info.stage=target?0:2;info.matches=target?1:0;return target;
 }
 info.stage=3;return 0;
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
 bool same=false;
 if(owned_actor==actor&&owned_expanded&&owned_kind==k){
  Q current=ptr(controller+0xb0);
  for(U depth=0;current&&depth<24;++depth){Node x{};if(!node(current,x))break;if(current==target){same=true;break;}if(x.parent==current)break;current=x.parent;}
 }
 if(!same&&!select_resolved(owner,target)){choice.nodes[k]=0;return 0;}
 choice.nodes[k]=target;
 choice.after_goal=(k==1&&!owned_goal);
 log_event("longarm_resolve ready actor=%d weapon=%d kind=%d node_hash=%08x",actor,w,k,n.hash);return 1;
}
static bool active(int actor,U k){
 if(k>=2)return false;
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
extern "C" void MS longarm_aim(int actor,void* target){
 original_aim(actor,target);
 if(!choice.after_goal)return;
 choice.after_goal=0;
 if(choice.actor!=actor||!rifle(choice.weapon)||owned_actor!=actor||owned_kind!=1||!owned_expanded)return;
 Q selected=choice.nodes[1],owner=owner_for(actor);Node n{};
 if(!selected||!owner||!node(selected,n)||!signature())return;
 // Initial AIM goal can replace a just-selected action node in locomotion.
 // Reassert once AFTER that goal; do not re-enter on each continued shot.
 if(select_resolved(owner,selected))log_event("longarm_after_goal actor=%d reapplied_once=1",actor);
}
template<class T>T& at(B* f,U o){return *reinterpret_cast<T*>(f+o);}
extern "C" void MS longarm_controls(B*);
extern "C" void MS longarm_tick(B* f){
 longarm_controls(f);
 const int actor=at<int>(f,0x768),w=at<int>(f,0x76c);
 if(!mod_enabled||!input_enabled||!rifle(w)||owned_actor!=actor||choice.actor!=actor||choice.weapon!=w||!owned_expanded||owned_kind<0||owned_kind>1||!(at<float>(f,0x828)>0.5f)){
  choice.prepare_value=choice.confirmation=choice.hold_until=0;return;
 }
 const Q now=at<Q>(f,0x40),confirmed=at<Q>(f,0x788);
 if(confirmed&&confirmed!=choice.confirmation&&now>=confirmed&&now-confirmed<=1000){
  choice.confirmation=confirmed;choice.hold_until=confirmed+1800;
 }
 if(at<B>(f,0x770)){
  // The supplied bolt-action log cycles for roughly one second. Wait for
  // that real cycle; never alter weapon cooldown, ammo or request checks.
  Q wanted=at<Q>(f,0x7f0)+1600;
  if(at<Q>(f,0x7f8)<wanted)at<Q>(f,0x7f8)=wanted;
  if(owned_kind==1&&at<B>(f,0x775)){
   Q& until=at<Q>(f,0x7b0);
   if(until>=300&&until!=choice.prepare_value){until=until-300+700;choice.prepare_value=until;log_event("longarm_prepare actor=%d window_ms=700",actor);}
  }else choice.prepare_value=0;
 }else choice.prepare_value=0;
 // A bounded hold spans the slow rifle cycle and the next physical click.
 // No click is generated, and empty clips/crouch/cancel end this extension.
 if(now<choice.hold_until&&release_at<choice.hold_until)release_at=choice.hold_until;
}
// This predicate replaces only the mod's early cover-passthrough check.
// It never changes the game's cover state or fabricates mouse input.
extern "C" int MS should_passthrough(int actor){
 choice.crouch_passthrough=0;
 int cover=original_cover(actor);if(cover)return cover;
 if(!rifle(weapon(actor)))return 0;
 const int pose=original_pose(actor);
 if(pose==2||pose==3){choice.crouch_passthrough=1;return 1;}
 return 0;
}
extern "C" void MS cancel_passthrough(void* controls,const char* reason,bool keep){
 // Real cover keeps its original behavior. Rifle crouch must release our
 // forced action node as well as its goals before ordinary fire resumes.
 const bool normal=choice.crouch_passthrough!=0;
 original_cancel(controls,normal?"longarm_crouch_passthrough":reason,normal?false:keep);
}
struct ReloadPending {int actor,weapon;Q since,next;};
extern "C" ReloadPending reload_pending;
extern "C" void MS mark_empty_stable(B* f){
 float ammo;asm("movss %%xmm6,%0":"=m"(ammo));
 union {float f;U u;} bits{ammo};
 if((bits.u&0x7f800000U)==0x7f800000U||!(ammo>=0&&ammo<=0.5f))return;
 // +68/+6C are scratch locals by the confirmation branch: +6C has
 // already been reused for position_valid. Controls at +768/+76C are
 // the stable actor/weapon pair used by the subsequent reload tick.
 reload_pending.actor=at<int>(f,0x768);reload_pending.weapon=at<int>(f,0x76c);
 reload_pending.since=at<Q>(f,0x40);reload_pending.next=reload_pending.since;
 if(reload_pending.weapon>=8&&reload_pending.weapon<=20)log_event("autoreload armed actor=%d weapon=%d stable_state=1",reload_pending.actor,reload_pending.weapon);
}
#include "signature.hpp"

// Longarm input intent has a lifetime independent of the held animation.
struct Vec {float x,y,z;};
struct Plan {Vec target;float heading;U id;B reticle,pad[3];};
static_assert(sizeof(Plan)==24);
struct RequestResult {int status,state;float cycle,alignment;};
extern "C" {
void MS original_queue(B*,bool);
bool MS original_plan(int,Plan*);
RequestResult* MS original_request(RequestResult*,U);
void MS original_shoot_goal(int,const Vec*);
void MS clear_shoot_goal();
extern Vec owned_target;extern float saved_heading;extern B owned_shoot_goal;
extern U input_state;extern Q rh_init,rh_push,rh_call;
}
struct Seen {U id=0;Q born=0;};
struct Intent {Seen seen[64];int actor=-1,weapon=-1;B* frame=nullptr;Q steer_until=0;U reports=0;};
Intent intent;
static bool scoped(B* f){return mod_enabled&&input_enabled&&at<int>(f,0x768)>=0&&rifle(at<int>(f,0x76c));}
static void reset_intent(){intent.actor=-1;intent.frame=nullptr;intent.steer_until=0;}
extern "C" void MS longarm_queue(B* f,bool prune){
 if(!rifle(at<int>(f,0x76c))){reset_intent();original_queue(f,prune);return;}
 if(!scoped(f)){reset_intent();return;}
 const int a=at<int>(f,0x768),w=at<int>(f,0x76c);
 if(intent.actor!=a||intent.weapon!=w){for(auto& x:intent.seen)x.id=0;intent.actor=a;intent.weapon=w;intent.steer_until=0;}
 intent.frame=f;
 Q& count=at<Q>(f,0x760);const Q head=at<Q>(f,0x758),now=at<Q>(f,0x40);
 if(count>64||head>=64)return;
 U kept=0,initial=static_cast<U>(count);
 for(U i=0;i<initial;++i){
  auto* p=reinterpret_cast<Plan*>(f+0x158+((head+i)&63)*24);
  Seen& seen=intent.seen[p->id&63];if(seen.id!=p->id){seen.id=p->id;seen.born=now;}
  const bool active=i==0&&at<B>(f,0x770);
  if(prune&&!active&&now>=seen.born&&now-seen.born>250){log_event("longarm_intent expired id=%u age_ms=%llu",p->id,now-seen.born);continue;}
  if(kept!=i)*reinterpret_cast<Plan*>(f+0x158+((head+kept)&63)*24)=*p;
  ++kept;
 }
 count=kept;
}
static bool finite_float(float f){union{float f;U u;}x{f};return (x.u&0x7f800000U)!=0x7f800000U;}
static bool refresh_target(B* f){
 Plan p{};const int actor=at<int>(f,0x768);
 if(!original_plan(actor,&p)||!finite_float(p.target.x)||!finite_float(p.target.y)||!finite_float(p.target.z)||!finite_float(p.heading))return false;
 const float dx=p.target.x-owned_target.x,dy=p.target.y-owned_target.y,dz=p.target.z-owned_target.z;
 float yaw=p.heading-saved_heading;while(yaw>180)yaw-=360;while(yaw< -180)yaw+=360;
 if(dx*dx+dy*dy+dz*dz<0.0001f&&yaw<=0.25f&&yaw>=-0.25f)return true;
 // Compare rays from the current camera origin, so a distant target's
 // motion along the ray does not count as an angular change.
 reinterpret_cast<void(MS*)(U)>(rh_init)(0x6b7677bfU);
 const Q* result=reinterpret_cast<const Q*(MS*)()>(rh_call)();
 const int camera=result?static_cast<int>(*result):0;
 Vec origin{};
 reinterpret_cast<void(MS*)(U)>(rh_init)(0x4a65f0b7U);
 reinterpret_cast<void(MS*)(Q)>(rh_push)(static_cast<U>(camera));
 reinterpret_cast<void(MS*)(Q)>(rh_push)(reinterpret_cast<Q>(&origin));
 reinterpret_cast<void(MS*)()>(rh_call)();
 const Vec a{owned_target.x-origin.x,owned_target.y-origin.y,owned_target.z-origin.z};
 const Vec b{p.target.x-origin.x,p.target.y-origin.y,p.target.z-origin.z};
 const float aa=a.x*a.x+a.y*a.y+a.z*a.z,bb=b.x*b.x+b.y*b.y+b.z*b.z,dot=a.x*b.x+a.y*b.y+a.z*b.z;
 if(!finite_float(aa)||!finite_float(bb)||!(aa>0.01f&&bb>0.01f)||dot<=0||dot*dot<aa*bb*0.9996954f||yaw>1||yaw< -1)intent.steer_until=at<Q>(f,0x40)+50;
 owned_target=p.target;saved_heading=p.heading;at<Vec>(f,0x7e4)=p.target;
 if(owned_goal)original_aim(actor,&owned_target);
 if(at<B>(f,0x770)&&!at<B>(f,0x777)&&owned_shoot_goal)original_shoot_goal(actor,&owned_target);
 if(intent.reports<8){++intent.reports;log_event("longarm_live_aim actor=%d updated=1",actor);}
 return true;
}
static bool aligned(int actor){
 Q owner=owner_for(actor),c=owner?ptr(owner+0x38):0,m=c?ptr(c+0xaa8):0,w=m?ptr(m+8):0;
 float alignment=1;
 return w&&ptr(w+8)==c&&read(w+0x368,&alignment,4)&&finite_float(alignment)&&alignment>=0&&alignment<=0.02f;
}
static void trigger_up(B* f){
 // Publish a released trigger without releasing the AIM goal or action node.
 const bool was_down=at<B>(f,0x152)||(input_state&1U);
 __atomic_store_n(&input_state,4U+(was_down?2U:0U),__ATOMIC_RELEASE);
 at<B>(f,0x152)=0;if(was_down)at<U>(f,0x7d0)=0;
}
extern "C" RequestResult* MS controlled_request(RequestResult* out,U actor){
 B* f=intent.frame;
 if(!f||!scoped(f)||at<int>(f,0x768)!=static_cast<int>(actor)||!rifle(at<int>(f,0x76c)))return original_request(out,actor);
 const bool fresh=refresh_target(f);
 if(!fresh||at<Q>(f,0x40)<intent.steer_until||!aligned(static_cast<int>(actor))){*out={-3,-1,-1,1};return out;}
 return original_request(out,actor);
}
extern "C" void MS longarm_controls(B* f){
 if(!scoped(f)||!(at<float>(f,0x828)>0.5f)||owned_actor!=at<int>(f,0x768)||choice.actor!=owned_actor||choice.weapon!=at<int>(f,0x76c)||!owned_expanded||owned_kind<0||owned_kind>1)return;
 longarm_queue(f,false);
 const Q now=at<Q>(f,0x40),count=at<Q>(f,0x760),head=at<Q>(f,0x758);
 if(at<B>(f,0x770)&&!at<B>(f,0x777)&&count&&count<=64&&head<64){
  U id=reinterpret_cast<Plan*>(f+0x158+head*24)->id;const Seen& seen=intent.seen[id&63];
  if(seen.id==id&&now>=seen.born&&now-seen.born>400){
   if(owned_shoot_goal)clear_shoot_goal();
   at<Q>(f,0x758)=(head+1)&63;at<Q>(f,0x760)=count-1;
   for(U o=0x770;o<=0x777;++o)if(o!=0x772)at<B>(f,o)=0;
   at<U>(f,0x7a4)=0;at<U>(f,0x7d4)=0;at<Q>(f,0x808)=0;
   trigger_up(f);log_event("longarm_intent abandoned id=%u age_ms=%llu pose_retained=1",id,now-seen.born);
  }
 }
 const bool fresh=refresh_target(f);
 if(at<B>(f,0x770)&&!at<B>(f,0x777)&&(!fresh||now<intent.steer_until||!aligned(owned_actor)))trigger_up(f);
}
