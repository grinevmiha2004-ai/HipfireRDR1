using U=unsigned;using Q=unsigned long long;using B=unsigned char;
#define MS __attribute__((ms_abi))
extern "C" {
int MS original_select(int,const char*);int MS original_playing(int,const char*);
int MS original_weapon(int);bool MS original_rapid(U,bool,bool);
Q MS actor_from(Q,U);Q MS read_pointer(Q);bool MS read_byte(Q,B*);
extern Q game_image,iat_rpm;
void MS log_event(const char*,...);
}
static bool eq(const char* a,const char* b){if(!a||!b)return false;while(*a&&*a==*b){++a;++b;}return *a==*b;}
static bool has(const char* s,const char* n){for(;*s;++s){const char* a=s;const char* b=n;while(*a&&*a==*b){++a;++b;}if(!*b)return true;}return false;}
static bool longarm(int w){return w>=8&&w<=20;}
struct Choice {int actor=-1,weapon=-1;const char* paths[4]{};U refused=0;};
Choice choice;
static int weapon(int actor){
 int w=original_weapon(actor);
 if(w>=0){if(choice.actor!=actor||choice.weapon!=w){choice.actor=actor;choice.weapon=w;for(auto& p:choice.paths)p=nullptr;choice.refused=0;}return w;}
 return w==-1&&choice.actor==actor?choice.weapon:-1;
}
static int kind(const char* path){
 if(eq(path,"default_character_Main\\Gunplay\\Pistol\\DeadEye\\PistolHoldStand"))return 0;
 if(eq(path,"default_character_Main\\tcwtnjb\\Pistol\\PistolAim\\DeadEye\\PistolHoldRun"))return 1;
 if(eq(path,"default_character_Main\\l8x7gpa\\Crouch\\t175e2a\\CrouchPistol\\PistolAim\\DeadEye\\PistolHoldStand"))return 2;
 if(eq(path,"default_character_Main\\l8x7gpa\\Crouch\\t175e2a\\CrouchPistol\\PistolAim\\DeadEye\\PistolHoldRun"))return 3;
 return -1;
}
// Candidate names must be accepted by SET_ACTION_NODE_FOR_ACTOR in the
// loaded game action tree. Their existence cannot be proven from RDR.exe.
static const char* candidate_path(int family,int k){
 if(family==0){switch(k){
 case 0:return "default_character_Main\\Gunplay\\Rifle\\DeadEye\\RifleHoldStand";
 case 1:return "default_character_Main\\tcwtnjb\\Rifle\\RifleAim\\DeadEye\\RifleHoldRun";
 case 2:return "default_character_Main\\l8x7gpa\\Crouch\\t175e2a\\CrouchRifle\\RifleAim\\DeadEye\\RifleHoldStand";
 case 3:return "default_character_Main\\l8x7gpa\\Crouch\\t175e2a\\CrouchRifle\\RifleAim\\DeadEye\\RifleHoldRun";
 }}
 else if(family==1){switch(k){
 case 0:return "default_character_Main\\Gunplay\\Shotgun\\DeadEye\\ShotgunHoldStand";
 case 1:return "default_character_Main\\tcwtnjb\\Shotgun\\ShotgunAim\\DeadEye\\ShotgunHoldRun";
 case 2:return "default_character_Main\\l8x7gpa\\Crouch\\t175e2a\\CrouchShotgun\\ShotgunAim\\DeadEye\\ShotgunHoldStand";
 case 3:return "default_character_Main\\l8x7gpa\\Crouch\\t175e2a\\CrouchShotgun\\ShotgunAim\\DeadEye\\ShotgunHoldRun";
 }}
 else if(family==2){switch(k){
 case 0:return "default_character_Main\\Gunplay\\LongArm\\DeadEye\\LongArmHoldStand";
 case 1:return "default_character_Main\\tcwtnjb\\LongArm\\LongArmAim\\DeadEye\\LongArmHoldRun";
 case 2:return "default_character_Main\\l8x7gpa\\Crouch\\t175e2a\\CrouchLongArm\\LongArmAim\\DeadEye\\LongArmHoldStand";
 case 3:return "default_character_Main\\l8x7gpa\\Crouch\\t175e2a\\CrouchLongArm\\LongArmAim\\DeadEye\\LongArmHoldRun";
 }}
 return nullptr;
}
extern "C" int MS select_node(int actor,const char* path){
 const int k=kind(path);
 if(k<0)return original_select(actor,path); // includes the root release node
 const int w=weapon(actor);
 if(!longarm(w))return original_select(actor,path);
 if(choice.paths[k])return original_select(actor,choice.paths[k]);
 const int first=w>=15&&w<=18?1:0;
 const int order[]={first,1-first,2};
 for(int family:order){
  const char* candidate=candidate_path(family,k);
  if(original_select(actor,candidate)){
   choice.paths[k]=candidate;
   log_event("longarm_node ready actor=%d weapon=%d kind=%d path=%s",actor,w,k,candidate);return 1;
  }
 }
 if(!(choice.refused&(1U<<k))){choice.refused|=1U<<k;log_event("longarm_node unavailable actor=%d weapon=%d kind=%d; action tree capture required",actor,w,k);}
 return 0; // Never substitute a pistol pose or a normal shoulder aim.
}
extern "C" int MS playing_node(int actor,const char* path){
 const int k=kind(path);if(k<0)return original_playing(actor,path);
 const int w=weapon(actor);if(!longarm(w))return original_playing(actor,path);
 return choice.paths[k]?original_playing(actor,choice.paths[k]):0;
}
using RPM=int(MS*)(void*,const void*,void*,Q,Q*);
static bool read(Q p,void* out,Q n){Q got=0;return p>=0x10000&&p<0x0000800000000000ULL-n&&reinterpret_cast<RPM>(iat_rpm)(reinterpret_cast<void*>(-1LL),reinterpret_cast<const void*>(p),out,n,&got)&&got==n;}
extern "C" bool MS clip_matches(const char* name,bool moving,bool crouched){
 if(!name)return false;
 if(!(has(name,"_rfl_")||has(name,"_rif_")||has(name,"_rpt_")||has(name,"_sht_")||has(name,"_sgn_")))return false;
 if(!(has(name,"_rpd_")||has(name,"_hip_")))return false;
 if((has(name,"_crc_")||has(name,"_crch_"))!=crouched)return false;
 if(!moving)return has(name,"_stn_");
 return has(name,"_run_")||(has(name,"_stn_")&&(crouched||has(name,"_fir")));
}
extern "C" bool MS rapid_pose(U actor,bool moving,bool crouched){
 if(!longarm(weapon(static_cast<int>(actor))))return original_rapid(actor,moving,crouched);
 const U k=(moving?1:0)+(crouched?2:0);
 // Only accept a track after this actor/weapon's requested node was accepted.
 if(!choice.paths[k])return false;
 if(original_playing(static_cast<int>(actor),choice.paths[k]))return true;
 Q owner=actor_from(game_image,actor);Q character=owner?read_pointer(owner+0x38):0;
 if(!character)return false;
 const U slots[]={0x530U,0x538U};
 for(U slot:slots){
  Q wrapper=read_pointer(character+slot),inner=wrapper?read_pointer(wrapper+0x10):0;B type=0;
  if(!inner||!read_byte(inner+0xa,&type)||type!=0xf)continue;
  Q clip=read_pointer(inner+0x50),name=clip?read_pointer(clip+0x10):0;
  char text[112]{};if(!name)continue;
  // Bounded individual reads tolerate names near inaccessible pages.
  bool complete=false;
  for(U j=0;j<sizeof(text);++j){B c=0;if(!read(name+j,&c,1))break;text[j]=static_cast<char>(c);if(!c){complete=true;break;}}
  if(complete&&clip_matches(text,moving,crouched))return true;
 }
 return false;
}
