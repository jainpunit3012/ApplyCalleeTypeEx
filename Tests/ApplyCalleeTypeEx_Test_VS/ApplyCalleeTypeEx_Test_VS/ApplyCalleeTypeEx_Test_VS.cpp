/*
 * ApplyCalleeTypeEx_Test_VS.cpp
 * Test binary for the ApplyCalleeTypeEx IDA Pro 9.3 plugin.
 * Generated with Claude AI (Anthropic) assistance — manually verified and tested.
 *
 * [1] PEB walk + export directory parsing -> WinExec
 * [2] GetProcAddress via locally resolved pointer -> ShellExecuteA
 * [3] ntdll!LdrGetProcedureAddress (not in IAT) -> MessageBoxA
 */

#pragma optimize("", off)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstring>

typedef NTSTATUS(NTAPI* pLdrGetProcedureAddress) (HMODULE, PANSI_STRING, WORD, PVOID*);
typedef HMODULE(WINAPI* pLoadLibraryA) (LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress) (HMODULE, LPCSTR);
typedef UINT(WINAPI* pWinExec) (LPCSTR, UINT);
typedef HINSTANCE(WINAPI* pShellExecuteA) (HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
typedef int (WINAPI* pMessageBoxA) (HWND, LPCSTR, LPCSTR, UINT);

static FARPROC find_export(HMODULE mod, const char* name)
{
    auto base = reinterpret_cast<const BYTE*>(mod);
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return nullptr;

    auto ied = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto names = reinterpret_cast<const DWORD*>(base + ied->AddressOfNames);
    auto ords = reinterpret_cast<const WORD*> (base + ied->AddressOfNameOrdinals);
    auto funcs = reinterpret_cast<const DWORD*>(base + ied->AddressOfFunctions);

    for (DWORD i = 0; i < ied->NumberOfNames; ++i)
        if (!strcmp(reinterpret_cast<const char*>(base + names[i]), name))
            return reinterpret_cast<FARPROC>(base + funcs[ords[i]]);
    return nullptr;
}

static HMODULE find_kernel32()
{
#if defined(_WIN64)
    auto peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PEB*>(__readfsdword(0x30));
#endif
    auto head = &peb->Ldr->InMemoryOrderModuleList;
    for (auto cur = head->Flink; cur != head; cur = cur->Flink) {
        auto entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!entry->FullDllName.Buffer) continue;
        WCHAR* leaf = entry->FullDllName.Buffer;
        for (WCHAR* p = leaf; *p; ++p)
            if (*p == L'\\' || *p == L'/') leaf = p + 1;
        if (!_wcsicmp(leaf, L"kernel32.dll"))
            return reinterpret_cast<HMODULE>(entry->DllBase);
    }
    return nullptr;
}

// [1] PEB walk + export directory parsing
static void technique_peb_winexec()
{
    HMODULE k32 = find_kernel32();
    if (!k32) { puts("[-] [1] kernel32 not found"); return; }

    pWinExec pfn = reinterpret_cast<pWinExec>(find_export(k32, "WinExec"));
    if (!pfn) { puts("[-] [1] WinExec not found"); return; }

    pfn("calc.exe", SW_SHOW);
}

// [2] GetProcAddress via locally resolved pointer
static void technique_getprocaddress_shellexecute()
{
    HMODULE k32 = find_kernel32();
    if (!k32) { puts("[-] [2] kernel32 not found"); return; }

    pLoadLibraryA   pfn_lla = reinterpret_cast<pLoadLibraryA>  (find_export(k32, "LoadLibraryA"));
    pGetProcAddress pfn_gpa = reinterpret_cast<pGetProcAddress>(find_export(k32, "GetProcAddress"));

    if (!pfn_lla || !pfn_gpa) { puts("[-] [2] prerequisites not found"); return; }

    HMODULE hShell = pfn_lla("shell32.dll");
    if (!hShell) { puts("[-] [2] shell32 load failed"); return; }

    pShellExecuteA pfn = reinterpret_cast<pShellExecuteA>(pfn_gpa(hShell, "ShellExecuteA"));
    if (!pfn) { puts("[-] [2] ShellExecuteA not found"); return; }

    pfn(nullptr, "open", "calc.exe", nullptr, nullptr, SW_SHOW);
}

// [3] ntdll!LdrGetProcedureAddress
static void technique_ldr_messagebox()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { puts("[-] [3] ntdll not found"); return; }

    pLdrGetProcedureAddress ldr = reinterpret_cast<pLdrGetProcedureAddress>(
        GetProcAddress(hNtdll, "LdrGetProcedureAddress"));
    if (!ldr) { puts("[-] [3] LdrGetProcedureAddress not found"); return; }

    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) { puts("[-] [3] user32 not found"); return; }

    const char name[] = "MessageBoxA";
    ANSI_STRING fn = {};
    fn.Buffer = const_cast<char*>(name);
    fn.Length = sizeof(name) - 1;
    fn.MaximumLength = sizeof(name);

    pMessageBoxA pfn = nullptr;
    if (!NT_SUCCESS(ldr(hUser32, &fn, 0, reinterpret_cast<PVOID*>(&pfn))) || !pfn) {
        puts("[-] [3] LdrGetProcedureAddress failed");
        return;
    }

    pfn(nullptr,
        "[1] WinExec via PEB walk\n"
        "[2] ShellExecuteA via GetProcAddress\n"
        "[3] MessageBoxA via LdrGetProcedureAddress",
        "ApplyCalleeTypeEx Test",
        MB_OK | MB_ICONINFORMATION);
}

int main()
{
    puts("[*] [1] PEB walk -> WinExec");
    technique_peb_winexec();
    Sleep(800);

    puts("[*] [2] GetProcAddress -> ShellExecuteA");
    technique_getprocaddress_shellexecute();
    Sleep(800);

    puts("[*] [3] LdrGetProcedureAddress -> MessageBoxA");
    technique_ldr_messagebox();

    return 0;
}