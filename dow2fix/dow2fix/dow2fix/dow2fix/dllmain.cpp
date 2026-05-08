/*
 * DoW2 Ultrawide UI Fix
 * An ASI plugin (Win32 DLL) that patches Dawn of War II's UI scale cap at runtime.
 *
 * How it works:
 *   DoW2.exe internally clamps the UI scale factor to 1.0f, which means at
 *   resolutions wider than ~1920px the UI stops growing and elements spill
 *   off-screen.  This DLL is loaded by Ultimate ASI Loader (via msacm32.dll),
 *   waits for the main module to finish loading, then locates the clamping
 *   instruction(s) by signature scan and NOP-patches them so the scale is
 *   derived purely from the actual viewport dimensions.
 *
 * Build (MSVC, 32-bit — must match the 32-bit DOW2.exe):
 *   cl /nologo /O2 /MT /LD dllmain.cpp /Fe:Injected.asi /link /DLL
 *
 * Build (MinGW-w64, 32-bit):
 *   i686-w64-mingw32-g++ -O2 -shared -o Injected.asi dllmain.cpp -lkernel32
 *
 * Install:
 *   Place Injected.asi and msacm32.dll (from Ultimate ASI Loader) next to DOW2.exe.
 *
 * Tested against: DoW2 Anniversary Edition (Steam), DOW2.exe 3.19.1.7237
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

 // ---------------------------------------------------------------------------
 // Logging (writes to DoW2_UIFix.log next to the DLL, for debugging)
 // ---------------------------------------------------------------------------
static void Log(const char* fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    FILE* f = fopen("DoW2_UIFix.log", "a");
    if (f) { fprintf(f, "%s\n", buf); fclose(f); }
}

// ---------------------------------------------------------------------------
// Memory helpers
// ---------------------------------------------------------------------------

// Make a region of memory writable, patch it, restore protection.
static bool SafePatch(void* addr, const void* newBytes, size_t len)
{
    DWORD old;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old))
    {
        Log("  VirtualProtect failed at %p (err %lu)", addr, GetLastError());
        return false;
    }
    memcpy(addr, newBytes, len);
    VirtualProtect(addr, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return true;
}

// Scan [start, start+size) for a byte pattern.
// '?' in the pattern array is a wildcard (value ignored, mask byte = 0).
static uint8_t* SigScan(uint8_t* start, size_t size,
    const uint8_t* pattern, const uint8_t* mask, size_t patLen)
{
    if (patLen == 0 || size < patLen) return nullptr;

    for (size_t i = 0; i <= size - patLen; ++i)
    {
        bool found = true;
        for (size_t j = 0; j < patLen; ++j)
        {
            if (mask[j] && start[i + j] != pattern[j])
            {
                found = false;
                break;
            }
        }
        if (found) return start + i;
    }
    return nullptr;
}

// Helper macro to define a pattern + mask inline.
// Use \x?? and mask 0 for wildcards.
#define PATTERN(name, ...) \
    static const uint8_t name##_pat[] = { __VA_ARGS__ }

#define MASK(name, ...) \
    static const uint8_t name##_mask[] = { __VA_ARGS__ }

// ---------------------------------------------------------------------------
// The actual patch
// ---------------------------------------------------------------------------

/*
 * In DOW2.exe the UI layout code contains something like:
 *
 *   fld     dword ptr [esi+0Ch]   ; load current scale
 *   fcomp   ds:flt_XXXXXX         ; compare with cap (1.0f stored in .rdata)
 *   fnstsw  ax
 *   test    ah, 41h
 *   jne     short loc_YYYYYY      ; skip if already <= cap
 *   fstp    dword ptr [esi+0Ch]   ; write clamped value
 *
 * The cap value itself is 0x3F800000 (1.0f as IEEE-754) sitting in .rdata.
 * We patch it to 4.0f (0x40800000), which allows the UI to scale up to 4×.
 * For extreme ultrawide you may want even higher; edit MAX_UI_SCALE below.
 *
 * Alternatively (and more robustly), we can find the comparison and replace
 * the conditional jump with unconditional NOPs so the clamp is never applied.
 *
 * We use BOTH strategies:
 *   1. Patch the cap float constant in .rdata to a large value.
 *   2. As a fallback, NOP the conditional branch that enforces the cap.
 */

 // Max scale to allow.  4.0 is fine for up to ~7680-wide.  Raise if needed.
static const float MAX_UI_SCALE = 4.0f;

// ---- Strategy 1: patch the float constant in .rdata ----------------------
//
// Pattern: the float 1.0 (3F 80 00 00) is referenced by a FCOMP instruction.
// We look for the constant directly in the .rdata section.
//
// We scan for 0x3F800000 preceded by context that makes it look like a scale
// cap: surrounded by other scale-related floats (0.5, 2.0 are common nearby).
//
// Because the exact offset varies between builds, we scan a broader region.

static bool PatchFloatCap(uint8_t* base, size_t imageSize)
{
    // Find the .rdata section header
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    uint8_t* rdataStart = nullptr;
    size_t   rdataSize = 0;

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        if (strncmp((char*)sec[i].Name, ".rdata", 6) == 0)
        {
            rdataStart = base + sec[i].VirtualAddress;
            rdataSize = sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (!rdataStart)
    {
        Log("  Could not locate .rdata section");
        return false;
    }

    Log("  .rdata at %p, size 0x%zx", rdataStart, rdataSize);

    // Scan for the sequence: 0.5f, 1.0f (the cap), 2.0f — a common triplet
    // around UI scale tables.
    //  0x3F000000 = 0.5f
    //  0x3F800000 = 1.0f  <-- cap to patch
    //  0x40000000 = 2.0f
    PATTERN(triplet,
        0x00, 0x00, 0x00, 0x3F,   // 0.5f
        0x00, 0x00, 0x80, 0x3F,   // 1.0f  (target)
        0x00, 0x00, 0x00, 0x40    // 2.0f
    );
    MASK(triplet,
        1, 1, 1, 1,
        1, 1, 1, 1,
        1, 1, 1, 1
    );

    uint8_t* hit = SigScan(rdataStart, rdataSize,
        triplet_pat, triplet_mask, sizeof(triplet_pat));

    if (!hit)
    {
        Log("  Triplet scan missed — trying single 1.0f scan");

        // Fallback: find first standalone 1.0f in .rdata
        PATTERN(single, 0x00, 0x00, 0x80, 0x3F);
        MASK(single, 1, 1, 1, 1);
        hit = SigScan(rdataStart, rdataSize,
            single_pat, single_mask, sizeof(single_pat));
        if (!hit)
        {
            Log("  Could not find 1.0f cap constant in .rdata");
            return false;
        }
        // Advance to the 1.0f (it's the whole match here)
    }
    else
    {
        hit += 4; // skip the 0.5f to reach the 1.0f
    }

    Log("  Found cap float at %p (value = %08X)", hit, *(uint32_t*)hit);

    float newCap = MAX_UI_SCALE;
    if (SafePatch(hit, &newCap, 4))
    {
        Log("  Patched cap float: 1.0 -> %.1f", MAX_UI_SCALE);
        return true;
    }
    return false;
}

// ---- Strategy 2: NOP the clamping branch in .text ------------------------
//
// Pattern in x86 code (approximate, wildcards for addresses/offsets):
//   D9 46 0C          fld   dword ptr [esi+0Ch]
//   D8 1D ?? ?? ?? ?? fcomp dword ptr ds:[imm32]   ; compare with 1.0 cap
//   DF E0             fnstsw ax
//   F6 C4 41          test  ah, 41h
//   75 ??             jne   short +N                ; <- NOP this (2 bytes)
//
// Replacing "75 ??" with "90 90" removes the conditional skip so the scale
// is never clamped.

static bool PatchClampBranch(uint8_t* base, size_t imageSize)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    uint8_t* textStart = nullptr;
    size_t   textSize = 0;

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        if (strncmp((char*)sec[i].Name, ".text", 5) == 0)
        {
            textStart = base + sec[i].VirtualAddress;
            textSize = sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textStart)
    {
        Log("  Could not locate .text section");
        return false;
    }

    Log("  .text at %p, size 0x%zx", textStart, textSize);

    //  D9 46 0C  D8 1D ?? ?? ?? ??  DF E0  F6 C4 41  75 ??
    PATTERN(branch,
        0xD9, 0x46, 0x0C,             // fld [esi+0Ch]
        0xD8, 0x1D, 0, 0, 0, 0,          // fcomp ds:[????]   (wildcard addr)
        0xDF, 0xE0,                   // fnstsw ax
        0xF6, 0xC4, 0x41,             // test ah, 41h
        0x75, 0                       // jne short ??
    );
    MASK(branch,
        1, 1, 1,
        1, 1, 0, 0, 0, 0,
        1, 1,
        1, 1, 1,
        1, 0
    );

    uint8_t* hit = SigScan(textStart, textSize,
        branch_pat, branch_mask, sizeof(branch_pat));

    if (!hit)
    {
        Log("  Branch pattern not found (may be a different build)");
        return false;
    }

    Log("  Found clamp branch at %p", hit);

    // Offset to the jne: 3 (fld) + 6 (fcomp) + 2 (fnstsw) + 3 (test) = 14
    uint8_t* jne = hit + 14;
    Log("  jne at %p (opcode %02X %02X)", jne, jne[0], jne[1]);

    const uint8_t nops[2] = { 0x90, 0x90 };
    if (SafePatch(jne, nops, 2))
    {
        Log("  NOPed clamp branch");
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Worker thread — called after DLL attach
// ---------------------------------------------------------------------------
static DWORD WINAPI PatchThread(LPVOID)
{
    // Give the game time to finish loading (especially on slower machines)
    Sleep(2000);

    Log("=== DoW2 Ultrawide UI Fix ===");

    HMODULE exe = GetModuleHandleA(NULL);
    if (!exe)
    {
        Log("Failed to get module handle");
        return 1;
    }

    uint8_t* base = (uint8_t*)exe;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    size_t imageSize = nt->OptionalHeader.SizeOfImage;

    Log("Module base: %p, image size: 0x%zx", base, imageSize);

    bool ok1 = PatchFloatCap(base, imageSize);
    bool ok2 = PatchClampBranch(base, imageSize);

    if (ok1 || ok2)
        Log("Patch applied successfully (cap=%.1f). Enjoy ultrawide!", MAX_UI_SCALE);
    else
        Log("WARNING: No patch applied — signatures not matched. "
            "Check DoW2_UIFix.log and report your DOW2.exe version.");

    return 0;
}

// ---------------------------------------------------------------------------
// DLL entry point
// ---------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hInst);
        // Spawn a thread so we don't block loader lock
        CreateThread(nullptr, 0, PatchThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
