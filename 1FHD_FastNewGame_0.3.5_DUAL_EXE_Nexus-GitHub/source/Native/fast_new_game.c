/* FHD_FastNewGame v0.3.5 dual EXE + NextDay, 2026 counter fallback: 32-bit Windows XenoNativeLoader Host API v1 plugin
   and SRHD Data.ScriptLibs standalone module.
   Supports two verified on-disk SHA256 fingerprints with fail-closed runtime code matching.
*/
typedef unsigned char U8;
typedef unsigned short U16;
typedef unsigned int U32;
typedef unsigned long long U64;
typedef int BOOL;
typedef U32 DWORD;
typedef void * HMODULE;
typedef U16 WCHAR;

#if defined(__GNUC__)
#define WINAPI __attribute__((stdcall))
#define EXPORT
#define NAKED __attribute__((naked))
#else
#define WINAPI __stdcall
#define EXPORT __declspec(dllexport)
#endif

#define ERROR_NOT_SUPPORTED 50u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_WRITE_FAULT 29u
#define PAGE_EXECUTE_READWRITE 0x40u

typedef BOOL (WINAPI *VP_FN)(void*, DWORD, DWORD, DWORD*);
typedef BOOL (WINAPI *FLUSH_FN)(void*, const void*, unsigned long);
typedef void* (WINAPI *PROC_FN)(void);
typedef int (WINAPI *PIN_FN)(U32, const U16*, void**);
typedef void (*VOID_FN)(void);
typedef void* (WINAPI *CREATE_FILE_FN)(const WCHAR*, DWORD, DWORD, void*, DWORD, DWORD, void*);
typedef BOOL (WINAPI *READ_FILE_FN)(void*, void*, DWORD, DWORD*, void*);
typedef BOOL (WINAPI *CLOSE_HANDLE_FN)(void*);
typedef DWORD (WINAPI *GET_MODULE_NAME_FN)(void*, WCHAR*, DWORD);

#if defined(__GNUC__)
NAKED static void* peb_address(void) {
    __asm__ volatile("movl %fs:0x30, %eax; ret");
}
static int ascii_eq_ci(const U8 *a, const char *b) {
    while (*a && *b) {
        U8 ca = *a++;
        U8 cb = (U8)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (U8)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (U8)(cb + 32);
        if (ca != cb) return 0;
    }
    return *a == 0 && *b == 0;
}
static void* find_module(const char *match) {
    U8 *peb = (U8*)peb_address();
    if (!peb) return 0;
    U8 *ldr = *(U8**)(peb + 0x0C);
    if (!ldr) return 0;
    U8 *head = ldr + 0x14;
    U8 *link = *(U8**)head;
    for (int i = 0; link && link != head && i < 48; ++i) {
        U8 *entry = link - 8;
        U8 *base = *(U8**)(entry + 0x18);
        const U16 *name = *(const U16**)(entry + 0x30);
        if (base && name) {
            int j = 0;
            for (; match[j]; ++j) {
                U16 c = name[j];
                if (c >= 'A' && c <= 'Z') c = (U16)(c + 32);
                U8 m = (U8)match[j];
                if (m >= 'A' && m <= 'Z') m = (U8)(m + 32);
                if (c != m) break;
            }
            if (!match[j] && !name[j]) return base;
        }
        link = *(U8**)link;
    }
    return 0;
}
static void* find_export(void *module, const char *wanted) {
    U8 *p = (U8*)module;
    if (!p || *(U16*)p != 0x5A4Du) return 0;
    U8 *nt = p + *(U32*)(p + 0x3C);
    if (*(U32*)nt != 0x00004550u || *(U16*)(nt + 24) != 0x010Bu) return 0;
    U8 *opt = nt + 24;
    U32 rva = *(U32*)(opt + 96);
    U32 len = *(U32*)(opt + 100);
    if (!rva) return 0;
    U8 *exp = p + rva;
    U32 count = *(U32*)(exp + 20);
    U32 n = *(U32*)(exp + 24);
    U32 *functions = (U32*)(p + *(U32*)(exp + 28));
    U32 *names = (U32*)(p + *(U32*)(exp + 32));
    U16 *ords = (U16*)(p + *(U32*)(exp + 36));
    for (U32 i = 0; i < n; ++i) {
        if (ascii_eq_ci(p + names[i], wanted)) {
            U16 ord = ords[i];
            if (ord >= count) return 0;
            U32 f = functions[ord];
            return (f >= rva && f < rva + len) ? 0 : (p + f);
        }
    }
    return 0;
}
static VP_FN resolve_vp(void) {
    void *k32 = find_module("kernel32.dll");
    void *kb = find_module("kernelbase.dll");
    VP_FN fn = (VP_FN)find_export(kb, "VirtualProtect");
    if (!fn) fn = (VP_FN)find_export(k32, "VirtualProtect");
    return fn;
}
static FLUSH_FN resolve_flush(void) {
    void *k32 = find_module("kernel32.dll");
    void *kb = find_module("kernelbase.dll");
    FLUSH_FN fn = (FLUSH_FN)find_export(kb, "FlushInstructionCache");
    if (!fn) fn = (FLUSH_FN)find_export(k32, "FlushInstructionCache");
    return fn;
}
static void pin_self(void *sym) {
    void *kb = find_module("kernelbase.dll");
    void *k32 = find_module("kernel32.dll");
    PIN_FN pin = (PIN_FN)find_export(kb, "GetModuleHandleExW");
    if (!pin) pin = (PIN_FN)find_export(k32, "GetModuleHandleExW");
    void *pinned = 0;
    if (pin) pin(1u | 4u, (const U16*)sym, &pinned);
}
static BOOL setprotect(void *p, U32 n, DWORD prot, DWORD *old) {
    VP_FN vp = resolve_vp();
    return vp ? vp(p, n, prot, old) : 0;
}
static void flush_code(void *addr, U32 n) {
    FLUSH_FN fl = resolve_flush();
    if (fl) fl((void*)-1, addr, n);
}
#endif

/* The hash is calculated on the unmodified disk EXE, not on relocated/patched PE memory. */
static const U32 shaK[64]={
0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
typedef struct {U32 h[8]; U64 n; U8 buffer[64]; U32 buffered;} SHA;
static U32 sha_rotate(U32 n,U32 k){return (n>>k)|(n<<(32-k));}
static void sha_transform(SHA *ctx,const U8 *p){
 U32 w[64],a,b,c,d,e,f,g,h,t1,t2;
 for(U32 i=0;i<16;i++)w[i]=((U32)p[4*i]<<24)|((U32)p[4*i+1]<<16)|((U32)p[4*i+2]<<8)|p[4*i+3];
 for(U32 i=16;i<64;i++){U32 s0=sha_rotate(w[i-15],7)^sha_rotate(w[i-15],18)^(w[i-15]>>3),s1=sha_rotate(w[i-2],17)^sha_rotate(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}
 a=ctx->h[0];b=ctx->h[1];c=ctx->h[2];d=ctx->h[3];e=ctx->h[4];f=ctx->h[5];g=ctx->h[6];h=ctx->h[7];
 for(U32 i=0;i<64;i++){U32 s1=sha_rotate(e,6)^sha_rotate(e,11)^sha_rotate(e,25),choice=(e&f)^(~e&g),s0=sha_rotate(a,2)^sha_rotate(a,13)^sha_rotate(a,22),major=(a&b)^(a&c)^(b&c);t1=h+s1+choice+shaK[i]+w[i];t2=s0+major;h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
 ctx->h[0]+=a;ctx->h[1]+=b;ctx->h[2]+=c;ctx->h[3]+=d;ctx->h[4]+=e;ctx->h[5]+=f;ctx->h[6]+=g;ctx->h[7]+=h;
}
static void sha_init(SHA *s){static const U32 v[8]={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};for(U32 i=0;i<8;i++)s->h[i]=v[i];s->n=0;s->buffered=0;}
static void sha_update(SHA *s,const U8 *b,U32 n){s->n+=(U64)n;for(U32 i=0;i<n;i++){s->buffer[s->buffered++]=b[i];if(s->buffered==64){sha_transform(s,s->buffer);s->buffered=0;}}}
static void sha_final(SHA *s,U8 digest[32]){U64 bits=s->n*8u;s->buffer[s->buffered++]=0x80u;if(s->buffered>56){while(s->buffered<64)s->buffer[s->buffered++]=0;sha_transform(s,s->buffer);s->buffered=0;}while(s->buffered<56)s->buffer[s->buffered++]=0;for(U32 i=0;i<8;i++)s->buffer[56+i]=(U8)(bits>>(56u-i*8u));sha_transform(s,s->buffer);for(U32 i=0;i<8;i++){digest[4*i]=(U8)(s->h[i]>>24);digest[4*i+1]=(U8)(s->h[i]>>16);digest[4*i+2]=(U8)(s->h[i]>>8);digest[4*i+3]=(U8)s->h[i];}}
static const U8 sha_A[32]={0x83,0x30,0x03,0x44,0xaf,0x80,0x2b,0xc5,0x1e,0x64,0x38,0x9c,0x58,0xf0,0x47,0xe5,0xaf,0xdf,0x19,0x5c,0x13,0x30,0x48,0x09,0x8b,0xe3,0x88,0x1f,0xae,0x29,0xed,0x98};
static const U8 sha_B[32]={0xe4,0x3a,0x4b,0x15,0x50,0x3c,0x70,0x5e,0xeb,0xe2,0xd8,0xce,0x57,0x78,0xc2,0xa2,0xfb,0x09,0x0d,0xb5,0x15,0xa3,0xfd,0x86,0xd3,0x19,0xe5,0xc5,0xaa,0x69,0x2e,0xbf};
/* Try the Host path, then the actual loaded EXE filename; loggable profile=0 on failure. */
static int hash_exe_file(const WCHAR *path, CREATE_FILE_FN op, READ_FILE_FN rd, CLOSE_HANDLE_FN cl){
 if(!path||!path[0])return 0;
 void *f=op(path,0x80000000u,1u|2u|4u,0,3u,0,0);
 if(!f||f==(void*)-1)return 0;
 U8 b[4096],hash[32];DWORD n;SHA h;sha_init(&h);U64 total=0;int ok=1;
 for(;;){if(!rd(f,b,sizeof(b),&n,0)){ok=0;break;}if(!n)break;total+=(U64)n;if(total>100000000u){ok=0;break;}sha_update(&h,b,n);}
 cl(f);if(!ok)return 0;sha_final(&h,hash);
 const U8 *ref=0;
 if(total==4995584u)ref=sha_A;else if(total==4533760u)ref=sha_B;else return 0;
 for(U32 i=0;i<32;i++)if(hash[i]!=ref[i])return 0;
 return ref==sha_A?1:2;
}
static int disk_exe_profile(const WCHAR *path){
 void *k=find_module("kernel32.dll"),*kb=find_module("kernelbase.dll");
 CREATE_FILE_FN op=(CREATE_FILE_FN)find_export(kb,"CreateFileW");if(!op)op=(CREATE_FILE_FN)find_export(k,"CreateFileW");
 READ_FILE_FN rd=(READ_FILE_FN)find_export(kb,"ReadFile");if(!rd)rd=(READ_FILE_FN)find_export(k,"ReadFile");
 CLOSE_HANDLE_FN cl=(CLOSE_HANDLE_FN)find_export(kb,"CloseHandle");if(!cl)cl=(CLOSE_HANDLE_FN)find_export(k,"CloseHandle");
 GET_MODULE_NAME_FN gm=(GET_MODULE_NAME_FN)find_export(k,"GetModuleFileNameW");if(!gm)gm=(GET_MODULE_NAME_FN)find_export(kb,"GetModuleFileNameW");
 if(!op||!rd||!cl)return 0;
 int profile=hash_exe_file(path,op,rd,cl);
 if(profile)return profile;
 WCHAR actual[1024];
 if(!gm||!gm(0,actual,1024))return 0;
 return hash_exe_file(actual,op,rd,cl);
}

typedef void (WINAPI *LOG_FN)(const WCHAR*, const WCHAR*);
typedef BOOL (WINAPI *CFG_BOOL_FN)(const WCHAR*, const WCHAR*, const WCHAR*, BOOL);
typedef int (WINAPI *CFG_INT_FN)(const WCHAR*, const WCHAR*, const WCHAR*, int, int, int);
typedef DWORD (WINAPI *CFG_STR_FN)(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, WCHAR*, DWORD);
typedef struct {
    U32 size, apiVersion;
    HMODULE gameModule;
    const WCHAR *gameRoot, *executablePath, *pluginRoot, *configPath;
    LOG_FN log;
    CFG_BOOL_FN configGetBool;
    CFG_INT_FN configGetInt;
    CFG_STR_FN configGetString;
} HOST;
typedef struct {
    U32 size, requiredHostApi;
    WCHAR id[64], version[32], description[160];
    U64 exclusiveCapabilities;
} INFO;

static const WCHAR kId[] = {'F','H','D','_','F','a','s','t','N','e','w','G','a','m','e',0};
static const WCHAR kConfigSection[] = {'F','a','s','t','N','e','w','G','a','m','e',0};
static const WCHAR kPresimKey[] = {'P','r','e','s','i','m','D','a','y','s',0};
static const WCHAR kCallsKey[] = {'D','i','r','e','c','t','C','a','l','c','u','l','a','t','i','o','n',0};
static const WCHAR kSuccess[] = {'p','a','t','c','h','_','a','p','p','l','i','e','d',0};
static const WCHAR kIdentityFail[] = {'r','e','j','e','c','t','e','d',':',' ','u','n','s','u','p','p','o','r','t','e','d',' ','e','x','e',0};
static const WCHAR kBytesFail[] = {'r','e','j','e','c','t','e','d',':',' ','b','y','t','e',' ','s','i','g','n','a','t','u','r','e',' ','m','i','s','m','a','t','c','h',0};
static const WCHAR kWriteFail[] = {'r','e','j','e','c','t','e','d',':',' ','V','i','r','t','u','a','l','P','r','o','t','e','c','t',' ','f','a','i','l','u','r','e',0};

static int g_patched = 0;
static int g_cfg_days = 60;
static int g_cfg_direct = 1;
static int g_active_now = 1;
/* A call through the active mod's OnStart/OnLoad script is direct evidence
   that this module is enabled. Consume it once, at the next presim loop. */
static int g_script_pending = 0;
/* 1 = full safe fast-start hooks, 2 = bounded hook for the verified 2026
   presim counter only. The latter never bypasses native thread sync. */
static int g_patch_mode = 0;

typedef struct {U32 loop1,loop2,loop3,limit,wrapper1,wrapper2,calc,jobptr,mods,nomods,cave,textStart,textEnd,dataStart,dataEnd,bssStart,bssEnd;} PROFILE;
static PROFILE g_profile;
static int g_detected_exe=-1;
static const WCHAR kHashFailed[]={'s','h','a','2','5','6',' ','n','o','t',' ','a','v','a','i','l','a','b','l','e',0};
static const WCHAR kOldFallback[]={'o','l','d',' ','e','x','e',':',' ','m','e','m','o','r','y',' ','s','i','g','n','a','t','u','r','e',' ','o','k',0};
static const WCHAR kNewUnverified[]={'n','e','w',' ','e','x','e',':',' ','s','i','g','n','a','t','u','r','e',' ','r','e','j','e','c','t','e','d',0};
static const WCHAR kSignatureFail[]={'r','e','j','e','c','t','e','d',':',' ','u','n','i','q','u','e',' ','c','o','d','e',' ','a','n','c','h','o','r','s',' ','n','o','t',' ','f','o','u','n','d',0};

static void copy_ascii(WCHAR *out, U32 n, const char *s) {
    U32 i = 0;
    if (!n) return;
    while (i + 1 < n && s[i]) {
        out[i] = (U8)s[i];
        ++i;
    }
    out[i] = 0;
}
static int bytes_match(const U8 *data, const U8 *expect, U32 count) {
    U32 i;
    for (i = 0; i < count; i++) if (data[i] != expect[i]) return 0;
    return 1;
}
static void bytes_copy(U8 *dst, const U8 *src, U32 count) {
    U32 i;
    for (i = 0; i < count; i++) dst[i] = src[i];
}
static int all_zero(const U8 *ptr, U32 n) {
    U32 i;
    for (i = 0; i < n; i++) if (ptr[i] != 0) return 0;
    return 1;
}
static U16 rd16(const U8 *p) { return (U16)(p[0] | (p[1] << 8)); }
static U32 rd32(const U8 *p) { return (U32)p[0] | ((U32)p[1] << 8) | ((U32)p[2] << 16) | ((U32)p[3] << 24); }
static void wr32(U8 *p, U32 n) { p[0] = (U8)n; p[1] = (U8)(n >> 8); p[2] = (U8)(n >> 16); p[3] = (U8)(n >> 24); }
static U8* game_va(U8 *game, U32 va) { return game + (va - 0x00400000u); }
static void generate_call(U8 out[5], U32 from, U32 to) { out[0] = 0xE8; wr32(out + 1, to - from - 5u); }
static void create_stub(U8 out[20],U32 va,U32 job){
 out[0]=0xA1;wr32(out+1,g_profile.jobptr);
 out[5]=0x8B;out[6]=0x00;out[7]=0xC7;out[8]=0x40;out[9]=0x2C;
 wr32(out+10,job);generate_call(out+14,va+14,g_profile.calc);out[19]=0xC3;
}
static int in_region(U32 va,U32 start,U32 end,U32 n){return va>=start&&va<end&&n<=end-va;}
static int in_text(U32 a,U32 n){return in_region(a,g_profile.textStart,g_profile.textEnd,n);}
static U8* memory_at(U32 va){return (U8*)va;}
static U32 read_call_target(U32 va){return (U32)(va+5u+rd32(memory_at(va)+1));}
static int parse_sections(U8* image){
 U32 pe=rd32(image+0x3C),op=pe+24u;if(pe<0x40u||pe>0x1000u)return 0;
 if(rd32(image+pe)!=0x00004550u||rd16(image+pe+4)!=0x14Cu||rd16(image+op)!=0x10Bu)return 0;
 if(rd32(image+op+28)!=0x00400000u)return 0;
 U32 count=rd16(image+pe+6),bytes=rd16(image+pe+20);if(count<3||count>16||bytes<96)return 0;
 g_profile.textStart=g_profile.textEnd=g_profile.dataStart=g_profile.dataEnd=g_profile.bssStart=g_profile.bssEnd=0;
 for(U32 i=0;i<count;i++){
  U8 *q=image+op+bytes+40*i;U32 v=rd32(q+12),sz=rd32(q+8);
  if(!sz||v>rd32(image+op+56)||sz>rd32(image+op+56)-v)continue;
  U32 st=0x00400000u+v,en=st+sz;
  if(q[0]=='.'&&q[1]=='t'&&q[2]=='e'&&q[3]=='x'&&q[4]=='t'){g_profile.textStart=st;g_profile.textEnd=en;}
  if(q[0]=='.'&&q[1]=='d'&&q[2]=='a'&&q[3]=='t'&&q[4]=='a'){g_profile.dataStart=st;g_profile.dataEnd=en;}
  if(q[0]=='.'&&q[1]=='b'&&q[2]=='s'&&q[3]=='s'){g_profile.bssStart=st;g_profile.bssEnd=en;}
 }
 return g_profile.textStart&&g_profile.dataStart&&g_profile.bssStart;
}
static int check_wrappers(U32 f1,U32 f2,U32 *jobptr){
 if(f1==f2||!in_text(f1,11)||!in_text(f2,11))return 0;
 U8 *a=memory_at(f1),*b=memory_at(f2);
 if(a[0]!=0xE8||a[5]!=0xE8||a[10]!=0xC3||b[0]!=0xE8||b[5]!=0xE8||b[10]!=0xC3)return 0;
 if(read_call_target(f1+5)!=read_call_target(f2+5))return 0;
 U32 w1=read_call_target(f1),w2=read_call_target(f2);
 if(!in_text(w1,17)||!in_text(w2,17))return 0;
 a=memory_at(w1);b=memory_at(w2);
 /* A1 [job object global] ; mov eax,[eax] ; mov [eax+2c],1 or 2. */
 if(a[0]!=0xA1||b[0]!=0xA1||rd32(a+1)!=rd32(b+1))return 0;
 if(a[5]!=0x8B||a[6]!=0||b[5]!=0x8B||b[6]!=0)return 0;
 if(a[7]!=0xC7||a[8]!=0x40||a[9]!=0x2C||rd32(a+10)!=1)return 0;
 if(b[7]!=0xC7||b[8]!=0x40||b[9]!=0x2C||rd32(b+10)!=2)return 0;
 U32 global=rd32(a+1);
 if(!in_region(global,g_profile.dataStart,g_profile.dataEnd,4))return 0;
 *jobptr=global;return 1;
}
static int resolve_loop(void){
 int solutions=0;
 for(U32 va=g_profile.textStart+0x100;va+8<g_profile.textEnd;va++){
  U8 *c=memory_at(va);
  if(c[0]!=0x81||c[1]!=0x7D||rd32(c+3)!=301u||c[7]!=0x75)continue;
  U32 calls[4],n=0,begin=va>0x110?va-0x110:g_profile.textStart;
  for(U32 j=begin;j+25<va;j++){
   U8 *t=memory_at(j);
   if(t[0]!=0xE8||t[5]!=0xA1||t[10]!=0x80||t[11]!=0x38||t[12]!=0||t[13]!=0x74||t[14]!=0x0D)continue;
   static const U8 tail[6]={0x33,0xC0,0x5A,0x59,0x59,0x64};
   int ok=1;for(U32 k=0;k<6;k++)if(t[15+k]!=tail[k])ok=0;
   if(!ok||t[21]!=0x89||t[22]!=0x10||t[23]!=0xE9)continue;
   /* Preserve last three matching call-sites leading to the 300-day loop. */
   if(n<4)calls[n++]=j;else{calls[0]=calls[1];calls[1]=calls[2];calls[2]=calls[3];calls[3]=j;}
  }
  if(n!=3)continue;
  if(read_call_target(calls[0])!=read_call_target(calls[2]))continue;
  U32 f1=read_call_target(calls[0]),f2=read_call_target(calls[1]),job=0;
  if(!check_wrappers(f1,f2,&job))continue;
  if(solutions++)return 0;
  g_profile.loop1=calls[0];g_profile.loop2=calls[1];g_profile.loop3=calls[2];g_profile.limit=va+3;
  g_profile.wrapper1=f1;g_profile.wrapper2=f2;g_profile.jobptr=job;
 }
 return solutions==1;
}
static int resolve_calc(void){
 static const U8 pre[15]={0x55,0x8B,0xEC,0xB9,0x33,0x00,0x00,0x00,0x6A,0x00,0x6A,0x00,0x49,0x75,0xF9};
 int found=0;
 for(U32 a=g_profile.textStart;a+120<g_profile.textEnd;a++){
  if(!bytes_match(memory_at(a),pre,15))continue;
  /* A generator thread directly dispatches job #1 based on [eax+2c]. */
  int job_check=0;
  for(U32 j=40;j<100;j++)if(memory_at(a)[j]==0x83&&memory_at(a)[j+1]==0x78&&memory_at(a)[j+2]==0x2C&&memory_at(a)[j+3]==1)job_check=1;
  if(!job_check)continue;
  if(found++)return 0;
  g_profile.calc=a;
 }
 return found==1;
}
static int resolve_modglobals(void){
 int found=0;
 for(U32 a=g_profile.textStart;a+220<g_profile.textEnd;a++){
  U8 *t=memory_at(a);
  if(t[0]!=0xB8||t[5]!=0x8B||t[6]!=0x55||t[7]!=0xF8||t[8]!=0xE8||t[13]!=0x68||t[18]!=0xFF||t[19]!=0x35)continue;
  U32 m=rd32(t+1),dup=rd32(t+20);
  if(m!=dup||!in_region(m,g_profile.bssStart,g_profile.bssEnd,4))continue;
  U32 no=0;
  for(U32 j=30;j<150;j++)if(t[j]==0x80&&t[j+1]==0x3D&&t[j+6]==0){U32 x=rd32(t+j+2);if(in_region(x,g_profile.dataStart,g_profile.dataEnd,1)){no=x;break;}}
  if(!no)continue;
  int repeats=0;
  for(U32 j=65;j<180;j++)if(t[j]==0x80&&t[j+1]==0x3D&&t[j+6]==0&&rd32(t+j+2)==no)repeats++;
  if(repeats<1)continue;
  if(found++)return 0;
  g_profile.mods=m;g_profile.nomods=no;
 }
 return found==1;
}
static int resolve_cave(U8 *exe){
 (void)exe;
 /* The zero-filled tail of the executable .text section, before .itext. */
 U32 begin=(g_profile.textEnd+15u)&~15u,stop=(g_profile.textEnd+0x700u)&~15u;
 if(stop>g_profile.dataStart)stop=g_profile.dataStart;
 for(U32 a=begin;a+0x50u<=stop;a+=16u){if(all_zero(memory_at(a),0x50u)){g_profile.cave=a;return 1;}}
 return 0;
}
static int resolve_profile_B(U8 *exe){
 if(!parse_sections(exe))return 0;
 if(!resolve_loop()||!resolve_calc()||!resolve_cave(exe))return 0;
 /* The 2026 build can move its mod-state globals. Their scanner is optional;
    the enabled OnStart ScriptLib hook is also a positive activation signal. */
 (void)resolve_modglobals();
 return 1;
}
/* Live mod-menu switch, addresses selected for the verified EXE profile. */
static int is_mod_enabled_in_memory(void){
 if(!g_profile.mods||!g_profile.nomods)return -1;
 if(*(volatile U8*)g_profile.nomods!=0)return 0;
 const WCHAR *mods=*(const WCHAR* const*)g_profile.mods;
 if(!mods||!*mods)return -1;
 static const char kNeedle[]="fhd_fastnewgame";
 for(int i=0;i<32768 && mods[i];i++){
  int k=0;for(;kNeedle[k];k++){WCHAR c=mods[i+k];if(!c)break;if(c>='A'&&c<='Z')c=(WCHAR)(c+32);if(c!=(WCHAR)kNeedle[k])break;}
  if(!kNeedle[k])return 1;
 }
 return 0;
}
static void update_loop_bound(U32 limit_val){
 U8 *t=memory_at(g_profile.limit);
 if(rd32(t)==limit_val)return;
 DWORD old=0,unused=0;U32 page=g_profile.limit&~0xFFFu;
 if(setprotect(memory_at(page),0x1000u,PAGE_EXECUTE_READWRITE,&old)){
  wr32(t,limit_val);flush_code(t,4);setprotect(memory_at(page),0x1000u,old,&unused);
 }
}
static void step_job1_loop(void){
 ((VOID_FN)(g_active_now && g_cfg_direct && g_patch_mode==1?g_profile.cave:g_profile.wrapper1))();
}
static void step_job2_loop(void){
 ((VOID_FN)(g_active_now && g_cfg_direct && g_patch_mode==1?g_profile.cave+0x20u:g_profile.wrapper2))();
}
static void step_job1_preloop(void){
 int active=is_mod_enabled_in_memory();
 /* If a script in the enabled FHD module called our DLL before warmup,
    trust that one-shot signal even if the 2026 EXE moved CurrentMod. */
 /* On 2026 fallback, if CurrentMod couldn't be located, retain the
    active module's OnStart decision for the duration of this warmup. */
 if(active==1 || g_script_pending!=0)g_active_now=1;
 else if(active==0)g_active_now=0;
 else if(g_patch_mode!=2)g_active_now=0;
 g_script_pending=0;
 update_loop_bound(g_active_now?(U32)(g_cfg_days+1):301u);
 step_job1_loop();
}

static int verified_pe_profile(U8 *image,int profile){
 U32 pe;const U8 *opt;
 if(!image||rd16(image)!=0x5A4Du)return 0;
 pe=rd32(image+0x3C);if(pe<0x40u||pe>0x1000u)return 0;
 if(rd32(image+pe)!=0x00004550u||rd16(image+pe+4)!=0x014Cu)return 0;
 opt=image+pe+24;if(rd16(opt)!=0x010Bu||rd32(opt+28)!=0x00400000u)return 0;
 if(profile==1)return rd32(image+pe+8)==0x68ECCC46u&&rd32(opt+56)==0x004D1000u&&rd32(opt+16)==0x00476AB4u;
 if(profile==2)return rd32(image+pe+8)==0x6AC53B97u&&rd32(opt+56)==0x00461000u&&rd32(opt+16)==0x00407A08u;
 return 0;
}
static void set_profile_A(void){
 g_profile.loop1=0x005D5D66u;g_profile.loop2=0x005D5D9Fu;g_profile.loop3=0x005D5DBBu;
 g_profile.limit=0x005D5DDDu;g_profile.wrapper1=0x004D75BCu;g_profile.wrapper2=0x004D75D0u;
 g_profile.calc=0x0072F91Cu;g_profile.jobptr=0x0088222Cu;g_profile.mods=0x00888EF0u;
 g_profile.nomods=0x0087A6E0u;g_profile.cave=0x00874720u;
}
static int is_already_patched(U8 *image){
 U8 stub[20];create_stub(stub,g_profile.cave,1);
 if(!bytes_match(game_va(image,g_profile.cave),stub,20))return 0;
 create_stub(stub,g_profile.cave+0x20u,2);
 if(!bytes_match(game_va(image,g_profile.cave+0x20u),stub,20))return 0;
 return 1;
}
static int verify_code(U8 *image){
 U8 call[5];const U8 prefix[2]={0x81,0x7D};
 if(!in_text(g_profile.loop1,5)||!in_text(g_profile.loop2,5)||!in_text(g_profile.loop3,5))return 0;
 if(!bytes_match(game_va(image,g_profile.limit-3u),prefix,2)||rd32(game_va(image,g_profile.limit))!=301u)return 0;
 generate_call(call,g_profile.loop1,g_profile.wrapper1);if(!bytes_match(game_va(image,g_profile.loop1),call,5))return 0;
 generate_call(call,g_profile.loop2,g_profile.wrapper2);if(!bytes_match(game_va(image,g_profile.loop2),call,5))return 0;
 generate_call(call,g_profile.loop3,g_profile.wrapper1);if(!bytes_match(game_va(image,g_profile.loop3),call,5))return 0;
 if(!all_zero(game_va(image,g_profile.cave),0x50u))return 0;
 static const U8 calcPre[7]={0x55,0x8B,0xEC,0xB9,0x33,0x00,0x00};
 if(!bytes_match(game_va(image,g_profile.calc),calcPre,7))return 0;
 return 1;
}

/* Writes at most a few short lines on initialization, no per-turn IO.
   It never edits game assets, PE files or any other mod. */
static void diagnostic(const char *message){
 void *k=find_module("kernel32.dll"), *kb=find_module("kernelbase.dll");
 GET_MODULE_NAME_FN gm=(GET_MODULE_NAME_FN)find_export(k,"GetModuleFileNameW");
 CREATE_FILE_FN op=(CREATE_FILE_FN)find_export(kb,"CreateFileW");
 if(!op) op=(CREATE_FILE_FN)find_export(k,"CreateFileW");
 typedef BOOL (WINAPI *WRITE_FN)(void*,const void*,DWORD,DWORD*,void*);
 WRITE_FN wr=(WRITE_FN)find_export(kb,"WriteFile");
 if(!wr) wr=(WRITE_FN)find_export(k,"WriteFile");
 CLOSE_HANDLE_FN cl=(CLOSE_HANDLE_FN)find_export(kb,"CloseHandle");
 if(!cl)cl=(CLOSE_HANDLE_FN)find_export(k,"CloseHandle");
 if(!gm||!op||!wr||!cl)return;
 WCHAR path[520];DWORD n=gm(0,path,520);if(!n||n>=520)return;
 while(n && path[n-1] != '\\' && path[n-1]!='/')n--;
 const char file[]="FHD_FastNewGame_035.log";
 for(U32 i=0;file[i];i++){if(n+i>=519)return;path[n+i]=(U16)(U8)file[i];path[n+i+1]=0;}
 void *f=op(path,0x00000004u,1u|2u,0,4u,0,0); /* FILE_APPEND_DATA, OPEN_ALWAYS */
 if(!f||f==(void*)-1)return;
 U32 len=0;while(message[len]&&len<200)len++;
 DWORD done=0;
 wr(f,message,len,&done,0);
 static const char end[]="\r\n";
 wr(f,end,2,&done,0);
 cl(f);
}
/* The supplied SolUtilities symbol table for PE 6AC53B97 gives the
   generator's exact warmup count and one in-loop tick call. Unlike the
   speculative all-function resolver, this option only rewrites a verified
   call and the original 301 constant. It does not overwrite unknown hooks. */
static DWORD try_new_presim_counter(U8 *exe, LOG_FN log){
 const U32 site=0x005BF3D6u, limit=0x005BF3F5u;
 if(!verified_pe_profile(exe,2) || !parse_sections(exe) ||
    !in_text(site,30) || !in_text(limit,13))return ERROR_NOT_SUPPORTED;
 U8 *t=memory_at(site),*b=memory_at(limit);
 static const U8 tick_tail[18]={0xA1,0,0,0,0,0x80,0x38,0,0x74,0x0D,0x33,0xC0,0x5A,0x59,0x59,0x64,0x89,0x10};
 static const U8 count_tail[9]={0x75,0xAA,0xC7,0x45,0xCC,0x12,0,0,0};
 if(t[0]!=0xE8 || rd32(b)!=301u || !bytes_match(b+4,count_tail,9))return ERROR_NOT_SUPPORTED;
 /* The interrupt/return unwind after the tick must match SolUtilities. */
 if(t[5]!=tick_tail[0] || t[10]!=tick_tail[5] ||
    !bytes_match(t+11,tick_tail+6,12))return ERROR_NOT_SUPPORTED;
 U32 wrapper=read_call_target(site);
 if(!in_text(wrapper,5))return ERROR_NOT_SUPPORTED;
 U32 page=site&~0xFFFu;
 if((limit&~0xFFFu)!=page)return ERROR_NOT_SUPPORTED;
 g_profile.loop1=site;g_profile.limit=limit;g_profile.wrapper1=wrapper;
 g_profile.wrapper2=0;g_profile.cave=0;
 /* New EXE's exact CurrentMod data might have moved; optional discovery. */
 g_profile.mods=0;g_profile.nomods=0;(void)resolve_modglobals();
 DWORD old=0,unused=0;
 if(!setprotect(memory_at(page),0x1000u,PAGE_EXECUTE_READWRITE,&old))return ERROR_WRITE_FAULT;
 U8 call[5];generate_call(call,site,(U32)(void*)step_job1_preloop);
 bytes_copy(memory_at(site),call,5);
 wr32(memory_at(limit),(U32)(g_cfg_days+1));
 flush_code(memory_at(site),limit+4u-site);
 setprotect(memory_at(page),0x1000u,old,&unused);
 g_patched=1;g_patch_mode=2;g_active_now=1;
 diagnostic("OK: 2026 EXE counter verified: 60-day fallback installed (native sync remains)");
 if(log)log(kId,kSuccess);
 return 0;
}
static DWORD apply_patch_internal(U8 *exe, int days, int direct, LOG_FN log, const WCHAR *exePath) {
    U8 call[5], stub[20];
    DWORD callOld = 0, caveOld = 0, unused = 0;

    if (days < 1 || days > 300) return ERROR_INVALID_PARAMETER;
    g_cfg_days = days;
    g_cfg_direct = direct;
    if (g_patched) {
        /* Enabled script calls are received before the generation warmup.
           Reaffirm the bound even when DLL was installed in a previous game. */
        if(g_script_pending)update_loop_bound((U32)(g_cfg_days+1));
        return 0;
    }
    if (exe != (U8*)0x00400000u) {if(log)log(kId,kIdentityFail);return ERROR_NOT_SUPPORTED;}
    /* Restore the proven v0.2.3 path for EXE A. Disk hashing is informational on
       this exact memory-verified build, not a new fatal dependency. This fixes
       both incorrect Host executablePath and forwarded CreateFileW discovery. */
    const int old_memory = verified_pe_profile(exe, 1);
    const int new_memory = verified_pe_profile(exe, 2);
    /* Validate the loaded PE, then the exact original instructions. The disk SHA is
       an extra consistency check, not a mandatory file-access dependency. */
    if (g_detected_exe < 0) g_detected_exe = disk_exe_profile(exePath);
    const int which = old_memory ? 1 : new_memory ? 2 : 0;
    if (!which || (g_detected_exe > 0 && g_detected_exe != which)) {
        diagnostic("REJECT: unsupported EXE or PE/hash disagreement");
        if (log) log(kId, kIdentityFail);
        return ERROR_NOT_SUPPORTED;
    }
    if (which == 1) {
        /* Original 0.2.3 offsets and calculations, with no behavior changes. */
        set_profile_A();
        if (!parse_sections(exe)) { diagnostic("REJECT: old EXE sections"); if(log)log(kId,kBytesFail); return ERROR_NOT_SUPPORTED; }
    } else if (!resolve_profile_B(exe)) {
        diagnostic("NOTICE: new EXE full fast-path not found, checking validated warmup counter");
        DWORD result=try_new_presim_counter(exe,log);
        if(result==0){pin_self((void*)apply_patch_internal);return 0;}
        diagnostic("REJECT: new EXE warmup counter also invalid/foreign hook");
        if (log) log(kId, kNewUnverified);
        return result;
    }
    pin_self((void*)apply_patch_internal);
    if (g_patched || is_already_patched(exe)) {
        g_patched = 1;
        return 0;
    }
    if (!verify_code(exe)) {
        if(which==2){
            DWORD result=try_new_presim_counter(exe,log);
            if(result==0)return 0;
        }
        diagnostic("REJECT: initial code mismatch or foreign hooks");
        if (log) log(kId, kBytesFail);
        return ERROR_NOT_SUPPORTED;
    }
    U32 codePage=g_profile.loop1&~0xFFFu,cavePage=g_profile.cave&~0xFFFu;
    if((g_profile.loop2&~0xFFFu)!=codePage || (g_profile.loop3&~0xFFFu)!=codePage || (g_profile.limit&~0xFFFu)!=codePage)return ERROR_NOT_SUPPORTED;
    if(((g_profile.cave+0x4Fu)&~0xFFFu)!=cavePage)return ERROR_NOT_SUPPORTED;
    if(!setprotect(memory_at(cavePage),0x1000u,PAGE_EXECUTE_READWRITE,&caveOld))goto failed;
    if(!setprotect(memory_at(codePage),0x1000u,PAGE_EXECUTE_READWRITE,&callOld)){
        setprotect(memory_at(cavePage),0x1000u,caveOld,&unused);goto failed;
    }
    create_stub(stub,g_profile.cave,1);bytes_copy(memory_at(g_profile.cave),stub,20);
    create_stub(stub,g_profile.cave+0x20u,2);bytes_copy(memory_at(g_profile.cave+0x20u),stub,20);
    generate_call(call,g_profile.loop1,(U32)(void*)step_job1_preloop);bytes_copy(memory_at(g_profile.loop1),call,5);
    generate_call(call,g_profile.loop2,(U32)(void*)step_job2_loop);bytes_copy(memory_at(g_profile.loop2),call,5);
    generate_call(call,g_profile.loop3,(U32)(void*)step_job1_loop);bytes_copy(memory_at(g_profile.loop3),call,5);
    /* Before releasing the code page, install the 60-day bound as well.
       The first loop callback will re-evaluate enabled state for live toggles. */
    wr32(memory_at(g_profile.limit),(U32)(g_cfg_days+1));
    flush_code(memory_at(g_profile.cave),0x50u);
    flush_code(memory_at(g_profile.loop1),g_profile.limit+4u-g_profile.loop1);
    setprotect(memory_at(codePage),0x1000u,callOld,&unused);
    setprotect(memory_at(cavePage),0x1000u,caveOld,&unused);
    g_patched = 1;g_patch_mode=1;
    diagnostic(which==1 ? "OK: old EXE, early limit 60, hooks active" : "OK: new EXE, early limit 60, hooks active");
    if (log) log(kId, kSuccess);
    return 0;
failed:
    diagnostic("REJECT: cannot write code pages");
    if (log) log(kId, kWriteFail);
    return ERROR_WRITE_FAULT;
}

EXPORT BOOL WINAPI XenoPlugin_Query(INFO *info) {
    if (!info || info->size < 520u) return 0;
    info->requiredHostApi = 1;
    copy_ascii(info->id, 64, "FHD_FastNewGame");
    copy_ascii(info->version, 32, "0.3.5");
    copy_ascii(info->description, 160, "FHD 60-day pre-sim and NextDay optimizations");
    if (info->size >= 528u) info->exclusiveCapabilities = 0;
    return 1;
}

EXPORT DWORD WINAPI XenoPlugin_Initialize(const HOST *host) {
    int days = 60, direct = 1;
    if (!host || host->size < 32u || host->apiVersion != 1 || !host->gameModule) return ERROR_INVALID_PARAMETER;
    if (host->size >= 40u && host->configGetInt) {
        days = host->configGetInt(host->configPath, kConfigSection, kPresimKey, 60, 1, 300);
    }
    if (host->size >= 36u && host->configGetBool) {
        direct = host->configGetBool(host->configPath, kConfigSection, kCallsKey, 1) != 0;
    }
    return apply_patch_internal((U8*)host->gameModule, days, direct, host->log, host->size>=24u?host->executablePath:0);
}

int FHDFastNewGame_Init(void) {
    /* This import only exists inside the enabled mod's original OnStart/OnLoad. */
    g_script_pending=1;
    U8 *peb = (U8*)peb_address();
    if (!peb) return -1;
    U8 *exe = *(U8**)(peb + 8);
    return (int)apply_patch_internal(exe, g_cfg_days, g_cfg_direct, 0, 0);
}

BOOL WINAPI DllMain(HMODULE hinstDLL, DWORD fdwReason, void *lpvReserved) {
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return 1;
}
