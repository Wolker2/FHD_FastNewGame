/* FHD_FastNewGame v0.2.3: 32-bit Windows XenoNativeLoader Host API v1 plugin
   and SRHD Data.ScriptLibs standalone module.
   Supports live in-game enable/disable from the SRHD Mod Menu without restarting Rangers.exe.
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
static void create_stub(U8 out[20], U32 va, U32 job) {
    static const U8 starter[10] = {0xA1, 0x2C, 0x22, 0x88, 0x00, 0x8B, 0x00, 0xC7, 0x40, 0x2C};
    bytes_copy(out, starter, 10);
    wr32(out + 10, job);
    generate_call(out + 14, va + 14, 0x0072F91Cu);
    out[19] = 0xC3;
}

/* Checks Rangers.exe in-memory CurrentMod UnicodeString (0x00888EF0) and NoMods flag (0x0087A6E0) */
static int is_mod_enabled_in_memory(void) {
    const U8 *no_mods = (const U8*)0x0087A6E0u;
    if (*no_mods != 0) return 0;
    const WCHAR *mods = *(const WCHAR* const*)0x00888EF0u;
    if (!mods || !*mods) return 0;
    static const char kNeedle[] = "fhd_fastnewgame";
    for (int i = 0; mods[i] && i < 32768; ++i) {
        int k = 0;
        for (; kNeedle[k]; ++k) {
            WCHAR c = mods[i + k];
            if (!c) break;
            if (c >= 'A' && c <= 'Z') c = (WCHAR)(c + 32);
            if (c != (WCHAR)kNeedle[k]) break;
        }
        if (!kNeedle[k]) return 1;
    }
    return 0;
}

static void update_loop_bound(U32 limit_val) {
    U8 *exe = (U8*)0x00400000u;
    U8 *target = game_va(exe, 0x005D5DDDu);
    if (rd32(target) == limit_val) return;
    DWORD oldProt = 0, unused = 0;
    if (setprotect(game_va(exe, 0x005D5000u), 0x1000u, PAGE_EXECUTE_READWRITE, &oldProt)) {
        wr32(target, limit_val);
        flush_code(target, 4u);
        setprotect(game_va(exe, 0x005D5000u), 0x1000u, oldProt, &unused);
    }
}

static void step_job1_loop(void) {
    if (g_active_now && g_cfg_direct) {
        ((VOID_FN)0x00874720u)();
    } else {
        ((VOID_FN)0x004D75BCu)();
    }
}

static void step_job2_loop(void) {
    if (g_active_now && g_cfg_direct) {
        ((VOID_FN)0x00874740u)();
    } else {
        ((VOID_FN)0x004D75D0u)();
    }
}

static void step_job1_preloop(void) {
    g_active_now = is_mod_enabled_in_memory();
    U32 target_limit = g_active_now ? (U32)(g_cfg_days + 1) : 301u;
    update_loop_bound(target_limit);
    step_job1_loop();
}

static int is_steamagog_release(U8 *image) {
    U32 pe;
    const U8 *opt;
    if (!image || rd16(image) != 0x5A4Du) return 0;
    pe = rd32(image + 0x3C);
    if (pe < 0x40 || pe > 0x1000) return 0;
    if (rd32(image + pe) != 0x00004550u || rd16(image + pe + 4) != 0x014Cu) return 0;
    if (rd32(image + pe + 8) != 0x68ECCC46u) return 0;
    opt = image + pe + 24;
    if (rd16(opt) != 0x010Bu || rd32(opt + 28) != 0x00400000u) return 0;
    if (rd32(opt + 56) != 0x004D1000u || rd32(opt + 16) != 0x00476AB4u) return 0;
    return 1;
}
static int is_already_patched(U8 *image) {
    U8 stub[20];
    create_stub(stub, 0x00874720u, 1);
    if (!bytes_match(game_va(image, 0x00874720u), stub, 20)) return 0;
    create_stub(stub, 0x00874740u, 2);
    if (!bytes_match(game_va(image, 0x00874740u), stub, 20)) return 0;
    return 1;
}
static int verify_code(U8 *image) {
    static const U8 loop_prefix[3] = {0x81, 0x7D, 0xF4};
    U8 call[5];
    if (!bytes_match(game_va(image, 0x005D5DDAu), loop_prefix, 3)) return 0;
    generate_call(call, 0x005D5D66u, 0x004D75BCu);
    if (!bytes_match(game_va(image, 0x005D5D66u), call, 5)) return 0;
    generate_call(call, 0x005D5D9Fu, 0x004D75D0u);
    if (!bytes_match(game_va(image, 0x005D5D9Fu), call, 5)) return 0;
    generate_call(call, 0x005D5DBBu, 0x004D75BCu);
    if (!bytes_match(game_va(image, 0x005D5DBBu), call, 5)) return 0;
    if (!all_zero(game_va(image, 0x00874720u), 0x48u)) return 0;
    {
        static const U8 calcPrologue[7] = {0x55, 0x8B, 0xEC, 0xB9, 0x33, 0x00, 0x00};
        if (!bytes_match(game_va(image, 0x0072F91Cu), calcPrologue, 7)) return 0;
    }
    return 1;
}

static DWORD apply_patch_internal(U8 *exe, int days, int direct, LOG_FN log) {
    U8 call[5], stub[20];
    DWORD callOld = 0, caveOld = 0, unused = 0;

    if (days < 1 || days > 300) return ERROR_INVALID_PARAMETER;
    g_cfg_days = days;
    g_cfg_direct = direct;
    if (exe != (U8*)0x00400000u || !is_steamagog_release(exe)) {
        if (log) log(kId, kIdentityFail);
        return ERROR_NOT_SUPPORTED;
    }
    pin_self((void*)apply_patch_internal);
    if (g_patched || is_already_patched(exe)) {
        g_patched = 1;
        return 0;
    }
    if (!verify_code(exe)) {
        if (log) log(kId, kBytesFail);
        return ERROR_NOT_SUPPORTED;
    }
    if (!setprotect(game_va(exe, 0x00874000u), 0x1000u, PAGE_EXECUTE_READWRITE, &caveOld)) goto failed;
    if (!setprotect(game_va(exe, 0x005D5000u), 0x1000u, PAGE_EXECUTE_READWRITE, &callOld)) {
        setprotect(game_va(exe, 0x00874000u), 0x1000u, caveOld, &unused);
        goto failed;
    }
    create_stub(stub, 0x00874720u, 1);
    bytes_copy(game_va(exe, 0x00874720u), stub, 20);
    create_stub(stub, 0x00874740u, 2);
    bytes_copy(game_va(exe, 0x00874740u), stub, 20);

    generate_call(call, 0x005D5D66u, (U32)(void*)step_job1_preloop);
    bytes_copy(game_va(exe, 0x005D5D66u), call, 5);
    generate_call(call, 0x005D5D9Fu, (U32)(void*)step_job2_loop);
    bytes_copy(game_va(exe, 0x005D5D9Fu), call, 5);
    generate_call(call, 0x005D5DBBu, (U32)(void*)step_job1_loop);
    bytes_copy(game_va(exe, 0x005D5DBBu), call, 5);

    flush_code(game_va(exe, 0x00874720u), 0x48u);
    flush_code(game_va(exe, 0x005D5D66u), 0x80u);
    setprotect(game_va(exe, 0x005D5000u), 0x1000u, callOld, &unused);
    setprotect(game_va(exe, 0x00874000u), 0x1000u, caveOld, &unused);
    g_patched = 1;
    if (log) log(kId, kSuccess);
    return 0;
failed:
    if (log) log(kId, kWriteFail);
    return ERROR_WRITE_FAULT;
}

EXPORT BOOL WINAPI XenoPlugin_Query(INFO *info) {
    if (!info || info->size < 520u) return 0;
    info->requiredHostApi = 1;
    copy_ascii(info->id, 64, "FHD_FastNewGame");
    copy_ascii(info->version, 32, "0.2.3");
    copy_ascii(info->description, 160, "FHD fast new-game generation (live toggle support)");
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
    return apply_patch_internal((U8*)host->gameModule, days, direct, host->log);
}

int FHDFastNewGame_Init(void) {
    U8 *peb = (U8*)peb_address();
    if (!peb) return -1;
    U8 *exe = *(U8**)(peb + 8);
    return (int)apply_patch_internal(exe, g_cfg_days, g_cfg_direct, 0);
}

BOOL WINAPI DllMain(HMODULE hinstDLL, DWORD fdwReason, void *lpvReserved) {
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return 1;
}
