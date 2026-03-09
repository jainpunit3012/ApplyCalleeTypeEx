# ApplyCalleeTypeEx — comprehensive test suite
# Compatible: IDA Pro 8.x through 9.3+
# Run via: File → Script file (Alt+F7) → select this file
# Expected: all sections pass with 0 failures.

import sys
import re
import os
import idaapi
import idc
import ida_kernwin
import ida_typeinf
import ida_ua
import ida_idp
import ida_nalt
import ida_ida

# ── Load plugin module ────────────────────────────────────────────────────────

def _load_plugin():
    import importlib.util
    candidates = [
        os.path.join(idaapi.get_user_idadir(), "plugins", "apply_callee_type_ex.py"),
        os.path.join(idaapi.idadir("plugins"), "apply_callee_type_ex.py"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "apply_callee_type_ex.py"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            spec = importlib.util.spec_from_file_location("act93", path)
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            ida_kernwin.msg("[TEST] Loaded from: %s\n" % path)
            return mod
    raise FileNotFoundError("apply_callee_type_ex.py not found.\nSearched:\n" +
                            "\n".join("  " + p for p in candidates))

P = _load_plugin()

# ── Test harness ──────────────────────────────────────────────────────────────

_passed = 0
_failed = 0

def _section(name):
    ida_kernwin.msg("\n%s\n  SECTION: %s\n" % ("─"*70, name))

def _ok(tag):
    global _passed
    _passed += 1
    ida_kernwin.msg("  [PASS] %s\n" % tag)

def _fail(tag, reason=""):
    global _failed
    _failed += 1
    ida_kernwin.msg("  [FAIL] %s%s\n" % (tag, ("  ← " + reason) if reason else ""))

def _check(cond, tag, reason=""):
    if cond:
        _ok(tag)
    else:
        _fail(tag, reason)

def _summary():
    ida_kernwin.msg("\n%s\n  %d passed, %d failed\n%s\n"
                    % ("═"*70, _passed, _failed, "═"*70))

# ── Helpers ───────────────────────────────────────────────────────────────────

_idati = ida_typeinf.get_idati()
_BADADDR = idaapi.BADADDR

def _tif_str(tif):
    return ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE, tif, "", "")

def _parse(raw):
    return P.parse_type_from_string(raw)

def _pre(raw):
    return P._preprocess_prototype(raw)

def _chk_parse(raw, tag, must_contain=None):
    tif = _parse(raw)
    ok  = tif is not None and (tif.is_func() or tif.is_funcptr())
    _check(ok, tag, "None or not func/funcptr")
    if ok and must_contain:
        s = _tif_str(tif)
        for sub in ([must_contain] if isinstance(must_contain, str) else must_contain):
            _check(sub in s, "%s [contains %r]" % (tag, sub), "got: " + s)
    return tif if ok else None

# ── SECTION A: _preprocess_prototype ─────────────────────────────────────────

_section("A — _preprocess_prototype")

# MSDN [in]/[out] brackets
r = _pre("UINT WinExec(\n  [in] LPCSTR lpCmdLine,\n  [in] UINT uCmdShow\n);")
_check("[in]" not in r,               "A-1  [in] stripped")
_check(";" in r,                      "A-1b semicolon")
_check("WinExec" in r,                "A-1c name preserved")
_check("LPCSTR" in r,                 "A-1d type preserved")
_check("\n" not in r,                 "A-1e no newlines")

# SAL _In_ / _Out_writes_bytes_
r = _pre("BOOL ReadFile(_In_ HANDLE h, _Out_writes_bytes_(n) LPVOID buf, DWORD n, _Out_opt_ LPDWORD rd, LPOVERLAPPED ov);")
_check("_In_" not in r,               "A-2  _In_ stripped")
_check("_Out_writes_bytes_" not in r, "A-2b _Out_writes_bytes_ stripped")
_check("_Out_opt_" not in r,          "A-2c _Out_opt_ stripped")
_check("ReadFile" in r,               "A-2d name preserved")

# [in,out] and [in, optional]
r = _pre("HRESULT Foo([in,out] PVOID p, [in, optional] DWORD d);")
_check("[in" not in r,                "A-3  [in,out] stripped")

# NTSYSAPI + NTAPI
r = _pre("NTSYSAPI\nNTSTATUS\nNTAPI\nLdrLoadDll(PWCHAR p, PULONG f, PUNICODE_STRING m, PHANDLE h);")
_check("NTSYSAPI" not in r,           "A-4  NTSYSAPI stripped")
_check("__stdcall" in r,              "A-4b NTAPI→__stdcall")
_check("LdrLoadDll" in r,             "A-4c name preserved")
_check("\n" not in r,                 "A-4d no newlines")

# Full ntdoc block
r = _pre("NTSYSAPI\nNTSTATUS\nNTAPI\nLdrGetProcedureAddress(\n"
         "    _In_ PVOID DllHandle,\n    _In_opt_ PCANSI_STRING ProcedureName,\n"
         "    _In_opt_ ULONG ProcedureNumber,\n    _Out_ PVOID *ProcedureAddress\n);")
_check("NTSYSAPI" not in r,           "A-5  NTSYSAPI stripped")
_check("__stdcall" in r,              "A-5b NTAPI→__stdcall")
_check("_In_opt_" not in r,           "A-5c _In_opt_ stripped")
_check("_Out_" not in r,              "A-5d _Out_ stripped")
_check("LdrGetProcedureAddress" in r, "A-5e name preserved")
_check("PVOID" in r,                  "A-5f type preserved")

# __declspec + WINAPI
r = _pre("__declspec(dllimport) BOOL WINAPI WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);")
_check("__declspec" not in r,         "A-6  __declspec stripped")
_check("__stdcall" in r,              "A-6b WINAPI→__stdcall")
_check("WriteFile" in r,              "A-6c name preserved")

# extern "C" { }
r = _pre('extern "C" { UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow); }')
_check("extern" not in r,             "A-7  extern C stripped")
_check("WinExec" in r,                "A-7b name preserved")
_check("{" not in r and "}" not in r, "A-7c braces stripped")

# WINBASEAPI
r = _pre("WINBASEAPI HANDLE WINAPI CreateFileA(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);")
_check("WINBASEAPI" not in r,         "A-8  WINBASEAPI stripped")
_check("__stdcall" in r,              "A-8b WINAPI→__stdcall")

# CALLBACK
r = _pre("LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);")
_check("CALLBACK" not in r,           "A-9  CALLBACK stripped")
_check("__stdcall" in r,              "A-9b CALLBACK→__stdcall")
_check("WndProc" in r,                "A-9c name preserved")

# FORCEINLINE
r = _pre("FORCEINLINE BOOL IsValidHandle(HANDLE h);")
_check("FORCEINLINE" not in r,        "A-10 FORCEINLINE stripped")

# [in,out]
r = _pre("HRESULT Foo([in] PVOID p1, [out] PVOID p2, [in,out] PVOID p3);")
_check("[in]" not in r and "[out]" not in r and "[in,out]" not in r, "A-11 all brackets stripped")

# typedef funcptr
r = _pre("typedef UINT (WINAPI *PWINEXEC)(LPCSTR lpCmdLine, UINT uCmdShow);")
_check(r.startswith("typedef"),       "A-12 typedef preserved")
_check("__stdcall" in r,              "A-12b WINAPI→__stdcall in typedef")
_check("PWINEXEC" in r,               "A-12c alias name preserved")

# bare funcptr — semicolon appended
r = _pre("UINT (__stdcall *)(LPCSTR, UINT)")
_check(r.endswith(";"),               "A-13 semicolon appended to bare funcptr")

# empty / whitespace
_check(_pre("") == "",                "A-14 empty → empty")
_check(_pre("   ") == "",             "A-14b whitespace → empty")

# NTHALAPI
r = _pre("NTHALAPI BOOLEAN HalQueryRealTimeClock(PTIME_FIELDS tf);")
_check("NTHALAPI" not in r,           "A-15 NTHALAPI stripped")

# DECLSPEC_NORETURN
r = _pre("DECLSPEC_NORETURN VOID RtlRaiseStatus(NTSTATUS s);")
_check("DECLSPEC_NORETURN" not in r,  "A-16 DECLSPEC_NORETURN stripped")

# multiple SAL per param
r = _pre("NTSTATUS Foo(_In_reads_bytes_(cb) _Out_writes_(n) PVOID p, ULONG cb, ULONG n);")
_check("_In_reads_bytes_" not in r,   "A-17 _In_reads_bytes_ stripped")
_check("_Out_writes_" not in r,       "A-17b _Out_writes_ stripped")

# static / inline
r = _pre("static inline BOOL MyFunc(DWORD d);")
_check("static" not in r,             "A-18 static stripped")
_check("inline" not in r,             "A-18b inline stripped")

# APIENTRY
r = _pre("int APIENTRY WinMain(HINSTANCE h1, HINSTANCE h2, LPSTR lp, int n);")
_check("APIENTRY" not in r,           "A-19 APIENTRY stripped")
_check("__stdcall" in r,              "A-19b APIENTRY→__stdcall")

# WINADVAPI
r = _pre("WINADVAPI BOOL WINAPI RegOpenKeyExA(HKEY,LPCSTR,DWORD,REGSAM,PHKEY);")
_check("WINADVAPI" not in r,          "A-20 WINADVAPI stripped")

# FASTCALL
r = _pre("int FASTCALL FastFunc(int a, int b);")
_check("FASTCALL" not in r,           "A-21 FASTCALL stripped")
_check("__fastcall" in r,             "A-21b FASTCALL→__fastcall")

# PASCAL
r = _pre("BOOL PASCAL OldFunc(HWND hwnd);")
_check("PASCAL" not in r,             "A-22 PASCAL stripped")
_check("__stdcall" in r,              "A-22b PASCAL→__stdcall")

# _Success_
r = _pre("_Success_(return != 0) BOOL TryParse(LPCSTR s, _Out_ PINT n);")
_check("_Success_" not in r,          "A-23 _Success_ stripped")

# WINCRYPT32API
r = _pre("WINCRYPT32API BOOL WINAPI CryptAcquireContextA(PHCRYPTPROV,LPCSTR,LPCSTR,DWORD,DWORD);")
_check("WINCRYPT32API" not in r,      "A-24 WINCRYPT32API stripped")

# exactly one semicolon
r = _pre("UINT WinExec(LPCSTR, UINT);")
_check(r.count(";") == 1,             "A-25 exactly one semicolon")

# CDECL
r = _pre("int CDECL printf(const char *fmt, ...);")
_check("CDECL" not in r,              "A-26 CDECL stripped")
_check("__cdecl" in r,                "A-26b CDECL→__cdecl")

# WINAPIV → __cdecl
r = _pre("int WINAPIV wsprintf(LPSTR buf, LPCSTR fmt, ...);")
_check("__cdecl" in r,                "A-27 WINAPIV→__cdecl")

# _COM_Outptr_
r = _pre("HRESULT QueryInterface(REFIID riid, _COM_Outptr_ void **ppv);")
_check("_COM_Outptr_" not in r,       "A-28 _COM_Outptr_ stripped")

# _Null_terminated_
r = _pre("BOOL WINAPI GetModuleFileNameA(HMODULE hModule, _Out_writes_(nSize) _Null_terminated_ LPSTR lpFilename, DWORD nSize);")
_check("_Null_terminated_" not in r,  "A-29 _Null_terminated_ stripped")
_check("_Out_writes_" not in r,       "A-29b _Out_writes_ stripped")
_check("GetModuleFileNameA" in r,     "A-29c name preserved")

# DECLSPEC_ALIGN
r = _pre("DECLSPEC_ALIGN(16) typedef struct { DWORD d; } ALIGNED;")
_check("DECLSPEC_ALIGN" not in r,     "A-30 DECLSPEC_ALIGN stripped")

# ── SECTION B: parse_type_from_string ────────────────────────────────────────

_section("B — parse_type_from_string")

# Plain prototypes
_chk_parse("UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow);",                                "B-1  WinExec plain",                     ["LPCSTR", "UINT"])
_chk_parse("UINT __stdcall WinExec(LPCSTR lpCmdLine, UINT uCmdShow);",                      "B-2  WinExec __stdcall",                 "__stdcall")
_chk_parse("HINSTANCE ShellExecuteA(HWND,LPCSTR,LPCSTR,LPCSTR,LPCSTR,INT);",               "B-3  ShellExecuteA plain",               "HINSTANCE")
_chk_parse("int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);",      "B-4  MessageBoxA plain",                 ["HWND", "LPCSTR"])
_chk_parse("int __stdcall MessageBoxA(HWND,LPCSTR,LPCSTR,UINT);",                           "B-5  MessageBoxA __stdcall",             "__stdcall")
_chk_parse("BOOL __stdcall WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);",          "B-6  WriteFile",                         ["BOOL", "HANDLE"])
_chk_parse("HANDLE CreateFileA(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);", "B-7  CreateFileA 7 params",          "HANDLE")
_chk_parse("LRESULT __stdcall WndProc(HWND,UINT,WPARAM,LPARAM);",                           "B-8  WndProc",                           "LRESULT")
_chk_parse("LPVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);",         "B-9  HeapAlloc WINAPI",                  "LPVOID")
_chk_parse("HANDLE WINAPI GetCurrentProcess(void);",                                         "B-10 GetCurrentProcess void arg")
_chk_parse("void __cdecl exit(int status);",                                                 "B-11 exit void return")
_chk_parse("VOID WINAPI ExitProcess(UINT uExitCode);",                                       "B-12 ExitProcess VOID (VOID→void preprocessed)")

# typedef funcptr
_chk_parse("typedef UINT (__stdcall *PWINEXEC)(LPCSTR, UINT);",                             "B-13 WinExec typedef funcptr")
_chk_parse("typedef HINSTANCE (__stdcall *PSHELLEXECUTEA)(HWND,LPCSTR,LPCSTR,LPCSTR,LPCSTR,INT);", "B-14 ShellExecuteA typedef")
_chk_parse("typedef NTSTATUS (__stdcall *PLDRLOADDLL)(PWCHAR,PULONG,PUNICODE_STRING,PHANDLE);",     "B-15 LdrLoadDll typedef")
_chk_parse("typedef int (__stdcall *PMSGBOXA)(HWND,LPCSTR,LPCSTR,UINT);",                   "B-16 MessageBoxA typedef")

# bare funcptr
_chk_parse("UINT (__stdcall *)(LPCSTR, UINT);",                                             "B-17 WinExec bare funcptr")
_chk_parse("int (__stdcall *)(HWND,LPCSTR,LPCSTR,UINT);",                                   "B-18 MessageBoxA bare funcptr")
_chk_parse("BOOL (__stdcall *)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);",                "B-19 WriteFile bare funcptr")

# MSDN [in]/[out] bracket forms (preprocessed transparently)
_chk_parse("UINT WinExec(\n  [in] LPCSTR lpCmdLine,\n  [in] UINT uCmdShow\n);",             "B-20 WinExec MSDN [in]")
_chk_parse("int MessageBoxA(\n  [in,optional] HWND hWnd,\n  [in,optional] LPCSTR lpText,\n  [in,optional] LPCSTR lpCaption,\n  [in] UINT uType\n);",
           "B-21 MessageBoxA MSDN [in,optional]")

# Full ntdoc blocks
_chk_parse("NTSYSAPI\nNTSTATUS\nNTAPI\nLdrGetProcedureAddress(\n"
           "    _In_ PVOID DllHandle,\n    _In_opt_ PVOID ProcedureName,\n"
           "    _In_opt_ ULONG ProcedureNumber,\n    _Out_ PVOID *ProcedureAddress\n);",
           "B-22 LdrGetProcedureAddress ntdoc")
_chk_parse("NTSYSAPI\nNTSTATUS\nNTAPI\nLdrLoadDll(\n"
           "    _In_opt_ PWCHAR PathToFile,\n    _In_opt_ PULONG Flags,\n"
           "    _In_ PUNICODE_STRING ModuleFileName,\n    _Out_ PHANDLE ModuleHandle\n);",
           "B-23 LdrLoadDll ntdoc")

# __declspec + CC macros
_chk_parse("__declspec(dllimport) BOOL WINAPI WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);",
           "B-24 WriteFile __declspec+WINAPI")
_chk_parse("WINBASEAPI HANDLE WINAPI CreateFileA(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);",
           "B-25 CreateFileA WINBASEAPI+WINAPI")
_chk_parse('extern "C" { UINT WinExec(LPCSTR, UINT); }',                                   "B-26 extern C")

# SAL-heavy
_chk_parse("BOOL ReadFile(_In_ HANDLE h, _Out_writes_bytes_(n) LPVOID buf, _In_ DWORD n, _Out_opt_ LPDWORD rd, _In_opt_ LPOVERLAPPED ov);",
           "B-27 ReadFile SAL")
_chk_parse("NTSTATUS NtAllocateVirtualMemory(_In_ HANDLE ph, _Inout_ PVOID *ba, _In_ ULONG_PTR zb, _Inout_ PSIZE_T rs, _In_ ULONG at, _In_ ULONG pp);",
           "B-28 NtAllocateVirtualMemory SAL")

# CC variants
_chk_parse("LRESULT CALLBACK WndProc(HWND,UINT,WPARAM,LPARAM);",                            "B-29 WndProc CALLBACK")
_chk_parse("BOOL PASCAL OldFunc(HWND hwnd, UINT msg);",                                     "B-30 OldFunc PASCAL")
_chk_parse("int FASTCALL FastFunc(int a, int b);",                                           "B-31 FastFunc FASTCALL")

# variadic
_chk_parse("int __cdecl printf(const char *fmt, ...);",                                     "B-32 printf variadic")
_chk_parse("int __cdecl sprintf(char *buf, const char *fmt, ...);",                         "B-33 sprintf variadic")

# many params
_chk_parse("BOOL WINAPI CreateProcessA(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);",
           "B-34 CreateProcessA 10 params")

# failure cases
_check(_parse("") is None,                                                                   "B-35 empty → None")
_check(_parse("   ") is None,                                                                "B-36 whitespace → None")
_check(_parse("this is ][ not a prototype @#$;") is None,                                   "B-37 garbage → None")
_check(_parse("int;") is None,                                                               "B-38 non-function type → None")
_check(_parse("DWORD dwValue;") is None,                                                     "B-39 variable decl → None")

# ── SECTION C: TIL type retrieval ────────────────────────────────────────────

_section("C — TIL named type retrieval")

def _chk_til(name, tag, expect_none=False):
    tif = P._get_named_type_and_deserialize(_idati, name)
    if expect_none:
        _check(tif is None, tag + " [expected None]")
    else:
        _check(tif is not None, tag, "None — TIL type not found")

_chk_til("WinExec",               "C-1  WinExec")
_chk_til("ShellExecuteA",         "C-2  ShellExecuteA")
_chk_til("MessageBoxA",           "C-3  MessageBoxA")
_chk_til("CreateFileA",           "C-4  CreateFileA")
_chk_til("WriteFile",             "C-5  WriteFile")
_chk_til("ReadFile",              "C-6  ReadFile")
_chk_til("RtlInitUnicodeString",  "C-7  RtlInitUnicodeString")
_chk_til("HeapAlloc",             "C-8  HeapAlloc")
_chk_til("CreateProcessA",        "C-9  CreateProcessA")
_chk_til("VirtualAlloc",          "C-10 VirtualAlloc")
# ntdll internals — None unless ntddk TIL loaded (not a test failure)
_chk_til("LdrGetProcedureAddress", "C-11 LdrGetProcedureAddress [None ok without ntddk]", expect_none=True)
_chk_til("NtAllocateVirtualMemory","C-12 NtAllocateVirtualMemory [None ok without ntddk]", expect_none=True)
_chk_til("__nonexistent_xyz_9999__","C-13 nonexistent → None",                             expect_none=True)

# ── SECTION D: _resolve_to_func_type ─────────────────────────────────────────

_section("D — _resolve_to_func_type")

PT_SIL = (getattr(ida_typeinf, "PT_SIL", None) or getattr(ida_typeinf, "PT_SILENT", None) or 0x1)
PT_TYP = getattr(ida_typeinf, "PT_TYP", 0x4)

def _chk_resolve(cleaned, tag, expect_none=False):
    tif = ida_typeinf.tinfo_t()
    if ida_typeinf.parse_decl(tif, None, cleaned, PT_TYP | PT_SIL) is None:
        _fail(tag, "parse_decl failed for: %r" % cleaned)
        return
    resolved = P._resolve_to_func_type(tif)
    if expect_none:
        _check(resolved is None, tag + " [expected None]")
    else:
        _check(resolved is not None and (resolved.is_func() or resolved.is_funcptr()), tag)

_chk_resolve("UINT WinExec(LPCSTR, UINT);",                         "D-1  plain func")
_chk_resolve("UINT (__stdcall *)(LPCSTR, UINT);",                   "D-2  bare funcptr")
_chk_resolve("typedef UINT (__stdcall *PWINEXEC)(LPCSTR, UINT);",   "D-3  typedef funcptr")
_chk_resolve("int MessageBoxA(HWND, LPCSTR, LPCSTR, UINT);",        "D-4  plain func 4 args")
_chk_resolve("int (__stdcall *)(HWND, LPCSTR, LPCSTR, UINT);",      "D-5  bare funcptr 4 args")
_chk_resolve("BOOL __stdcall WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);", "D-6 WriteFile")
_chk_resolve("int __cdecl printf(const char*, ...);",               "D-7  printf variadic")
_chk_resolve("DWORD;",    "D-8  DWORD scalar → None",  expect_none=True)
_chk_resolve("PVOID;",    "D-9  PVOID scalar → None",  expect_none=True)
_chk_resolve("int;",      "D-10 int scalar → None",    expect_none=True)

# ── SECTION E: apply_type_to_call ────────────────────────────────────────────

_section("E — apply_type_to_call")

def _find_indirect_calls(limit=20):
    import ida_segment
    results = []
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        if not seg or seg.sclass != ida_segment.SEG_CODE:
            continue
        ea = seg.start_ea
        while ea < seg.end_ea and len(results) < limit:
            insn = ida_ua.insn_t()
            if (ida_ua.decode_insn(insn, ea) and ida_idp.is_call_insn(insn)
                    and idc.get_operand_type(ea, 0) not in (idc.o_near, idc.o_far)):
                results.append(ea)
            ea = idc.next_head(ea, seg.end_ea)
        if len(results) >= limit:
            break
    return results

def _find_direct_call():
    import ida_segment
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        if not seg or seg.sclass != ida_segment.SEG_CODE:
            continue
        ea = seg.start_ea
        while ea < seg.end_ea:
            insn = ida_ua.insn_t()
            if (ida_ua.decode_insn(insn, ea) and ida_idp.is_call_insn(insn)
                    and idc.get_operand_type(ea, 0) in (idc.o_near, idc.o_far)):
                return ea
            ea = idc.next_head(ea, seg.end_ea)
    return _BADADDR

indirect_eas = _find_indirect_calls()
direct_ea    = _find_direct_call()

if not indirect_eas:
    ida_kernwin.msg("  [INFO] No indirect CALLs found — load PoC binary for E tests.\n")
else:
    ida_kernwin.msg("  [INFO] %d indirect CALL site(s) found.\n" % len(indirect_eas))
    protos = [
        "UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow);",
        "int MessageBoxA(HWND,LPCSTR,LPCSTR,UINT);",
        "HINSTANCE ShellExecuteA(HWND,LPCSTR,LPCSTR,LPCSTR,LPCSTR,INT);",
        "BOOL __stdcall WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);",
        "typedef UINT (__stdcall *PWINEXEC)(LPCSTR, UINT);",
        "typedef int (__stdcall *PMSGBOXA)(HWND,LPCSTR,LPCSTR,UINT);",
        "UINT (__stdcall *)(LPCSTR, UINT);",
        "UINT WinExec(\n  [in] LPCSTR lpCmdLine,\n  [in] UINT uCmdShow\n);",
        "int MessageBoxA(\n  [in,optional] HWND hWnd,\n  [in,optional] LPCSTR lpText,\n  [in,optional] LPCSTR lpCaption,\n  [in] UINT uType\n);",
        "NTSYSAPI\nNTSTATUS\nNTAPI\nLdrGetProcedureAddress(\n    _In_ PVOID DllHandle,\n    _In_opt_ PVOID ProcedureName,\n    _In_opt_ ULONG ProcedureNumber,\n    _Out_ PVOID *ProcedureAddress\n);",
        "WINBASEAPI HANDLE WINAPI CreateFileA(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);",
        "__declspec(dllimport) BOOL WINAPI WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);",
    ]
    for i, proto in enumerate(protos):
        ea  = indirect_eas[i % len(indirect_eas)]
        tif = P.parse_type_from_string(proto)
        tag = "E-%-2d 0x%X" % (i + 1, ea)
        if tif is None:
            _fail(tag, "parse returned None for: %r" % proto[:50])
            continue
        _check(P.apply_type_to_call(ea, tif), tag)

# Rejection tests — always run regardless of binary
if direct_ea != _BADADDR:
    tif = P.parse_type_from_string("int __cdecl dummy(void);")
    _check(not P.apply_type_to_call(direct_ea, tif),
           "E-R1 direct CALL rejected at 0x%X" % direct_ea)
else:
    ida_kernwin.msg("  [INFO] No direct CALL found for E-R1.\n")

tif = P.parse_type_from_string("UINT WinExec(LPCSTR, UINT);")
_check(not P.apply_type_to_call(0, tif),     "E-R2 address 0 rejected")
_check(not P.apply_type_to_call(_BADADDR, tif), "E-R3 BADADDR rejected")
_check(P.parse_type_from_string("garbage $$$;") is None, "E-R4 garbage → None (won't reach apply)")

# ── SECTION F: func → funcptr wrapping ───────────────────────────────────────

_section("F — func → funcptr wrapping")

if indirect_eas:
    ea = indirect_eas[0]
    tif_func = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(tif_func, None, "UINT WinExec(LPCSTR, UINT);", PT_TYP | PT_SIL)
    _check(tif_func.is_func(),                    "F-1  raw func tif.is_func()")
    _check(P.apply_type_to_call(ea, tif_func),    "F-2  apply succeeds with func tif (auto-wrapped)")

    tif_ptr = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(tif_ptr, None, "UINT (__stdcall *)(LPCSTR, UINT);", PT_TYP | PT_SIL)
    _check(tif_ptr.is_funcptr(),                  "F-3  funcptr tif.is_funcptr()")
    _check(P.apply_type_to_call(ea, tif_ptr),     "F-4  apply succeeds with funcptr tif")
else:
    ida_kernwin.msg("  [INFO] No indirect CALL — F tests skipped.\n")

# ── SECTION G: API surface (IDA 8/9 parity) ──────────────────────────────────

_section("G — API surface / IDA version parity")

_check(ida_typeinf.get_idati() is not None,             "G-1  get_idati() valid")
_check(hasattr(ida_ida, "inf_is_64bit"),                "G-2  ida_ida.inf_is_64bit")
_check(hasattr(ida_ida, "inf_is_32bit_exactly"),        "G-3  ida_ida.inf_is_32bit_exactly")
_check(hasattr(ida_typeinf, "apply_callee_tinfo"),      "G-4  apply_callee_tinfo")
_check(hasattr(ida_typeinf, "choose_named_type"),       "G-5  choose_named_type")
_check(hasattr(ida_typeinf, "choose_local_tinfo"),      "G-6  choose_local_tinfo")
pt_sil = getattr(ida_typeinf, "PT_SIL", None) or getattr(ida_typeinf, "PT_SILENT", None)
_check(pt_sil is not None,                              "G-7  PT_SIL/PT_SILENT (0x%x)" % (pt_sil or 0))
pt_typ = getattr(ida_typeinf, "PT_TYP", None)
_check(pt_typ is not None,                              "G-8  PT_TYP (0x%x)" % (pt_typ or 0))
ntf = getattr(ida_typeinf, "NTF_SYMM", None)
_check(ntf is not None,                                 "G-9  NTF_SYMM (0x%x)" % (ntf or 0))
_check(hasattr(ida_idp, "is_call_insn"),                "G-10 is_call_insn")
_check(hasattr(ida_kernwin, "BWN_DISASM"),              "G-11 BWN_DISASM")
_check(hasattr(ida_kernwin, "BWN_PSEUDOCODE"),          "G-12 BWN_PSEUDOCODE")
_check(hasattr(ida_kernwin, "register_action"),         "G-13 register_action")
_check(hasattr(ida_kernwin, "unregister_action"),       "G-14 unregister_action")
_check(hasattr(ida_kernwin, "action_desc_t"),           "G-15 action_desc_t")
_check(hasattr(ida_kernwin, "attach_action_to_menu"),   "G-16 attach_action_to_menu")
_check(hasattr(ida_kernwin, "attach_action_to_popup"),  "G-17 attach_action_to_popup")
_check(hasattr(ida_kernwin, "UI_Hooks"),                "G-18 UI_Hooks")
_check(hasattr(P.ApplyCalleeTypeHooks,
               "finish_populating_widget_popup"),        "G-19 finish_populating_widget_popup")

# Forbidden removed APIs must not appear in executable code
import inspect
src = inspect.getsource(P)
for forbidden, tag in (
    ("import ida_struct",  "G-20 no ida_struct"),
    ("import ida_enum",    "G-21 no ida_enum"),
    ("get_inf_structure",  "G-22 no get_inf_structure"),
    ("using_ida7api",      "G-23 no using_ida7api"),
    ("choose_named_type2", "G-24 no choose_named_type2 in code"),
):
    bad_lines = [l for l in src.splitlines()
                 if forbidden in l and not l.strip().startswith('#')]
    _check(len(bad_lines) == 0, tag,
           "found in: %s" % bad_lines[:1])

_check(P._QT_LAYER in ("pyside6", "pyqt5") or not P._HAS_QT,
       "G-25 Qt layer: %s" % (P._QT_LAYER or "none"))
_check(P.ApplyCalleeTypePlugin.flags == idaapi.PLUGIN_KEEP, "G-26 PLUGIN_KEEP")
_check(P.ACTION_HOTKEY == "Shift+A",                          "G-27 ACTION_HOTKEY=Alt+J")
_check(P.MENU_PATH.startswith("Edit/"),                     "G-28 MENU_PATH starts with Edit/")
_check(P.ApplyCalleeTypePlugin.wanted_hotkey == "",         "G-29 wanted_hotkey empty")

# ── SECTION H: preprocessor edge cases ───────────────────────────────────────

_section("H — preprocessor edge cases")

# annotation-only input → empty body after stripping
r = _pre("[in] [out] _In_ _Out_")
_check(r.strip().rstrip(';').strip() == "",   "H-1  annotation-only → empty body")

# pointer / const / array preserved
_check("PVOID" in _pre("PVOID *NtFunc(PVOID **pp);"),        "H-2  PVOID* preserved")
_check("const" in _pre("int WINAPI Bar(const char *s);"),    "H-3  const preserved")
_check("arr" in _pre("void WINAPI Foo(BYTE arr[16]);"),      "H-4  array param preserved")

# double annotation — no double spaces in preserved names
r = _pre("NTSTATUS NTAPI Func(_In_ _Reserved_ PVOID Reserved);")
_check("NTSTATUS" in r and "Func" in r,       "H-5  names survive double annotation")
_check("_In_" not in r and "_Reserved_" not in r, "H-5b both SAL stripped")

# two CC macros (edge case in bad copy-paste)
r = _pre("HRESULT WINAPI CALLBACK DoubleMacro(HWND h);")
_check("WINAPI" not in r and "CALLBACK" not in r, "H-6  both CC macros consumed")
_check("__stdcall" in r,                       "H-6b __stdcall present")

# _COM_Outptr_ stripped
r = _pre("HRESULT QI(REFIID riid, _COM_Outptr_ void **ppv);")
_check("_COM_Outptr_" not in r,                "H-7  _COM_Outptr_ stripped")

# trailing whitespace / missing semicolon — always ends with exactly one ;
for s in ("UINT WinExec(LPCSTR, UINT)  ",
          "UINT WinExec(LPCSTR, UINT);  ",
          "UINT WinExec(LPCSTR, UINT)"):
    r = _pre(s)
    _check(r.endswith(";") and r.count(";") == 1, "H-8  semicolon normalised (%r)" % s[:30])

# NTAPI in middle of declaration (not at start)
r = _pre("typedef NTSTATUS (NTAPI *PFUNC)(PVOID, ULONG);")
_check("__stdcall" in r,                       "H-9  NTAPI→__stdcall inside typedef")
_check("NTAPI" not in r,                       "H-9b NTAPI consumed")

# ── SECTION I: round-trip fidelity ───────────────────────────────────────────

_section("I — parse round-trip fidelity")

def _rt(raw, must_contain, tag):
    tif = _parse(raw)
    if tif is None:
        _fail(tag, "parse returned None")
        return
    s = _tif_str(tif)
    for sub in ([must_contain] if isinstance(must_contain, str) else must_contain):
        _check(sub in s, "%s [%r in output]" % (tag, sub), "got: " + s)

_rt("UINT WinExec(LPCSTR, UINT);",                    ["LPCSTR", "UINT"],  "I-1  WinExec args")
_rt("int MessageBoxA(HWND,LPCSTR,LPCSTR,UINT);",       ["HWND", "LPCSTR"], "I-2  MessageBoxA args")
_rt("UINT __stdcall WinExec(LPCSTR, UINT);",           "__stdcall",         "I-3  __stdcall preserved")
_rt("UINT (__stdcall *)(LPCSTR, UINT);",               "__stdcall",         "I-4  funcptr __stdcall")
# I-5: __cdecl is always the implicit default CC — IDA's printer never emits it.
_rt("int __cdecl printf(const char*, ...);",           ["int", "const char"], "I-5  printf round-trip (cdecl is default, printer omits it)")
_rt("BOOL __stdcall WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);",
    ["BOOL", "__stdcall"],                                                   "I-6  WriteFile full")

# ── Diagnostics ───────────────────────────────────────────────────────────────

_section("Z — Diagnostics")
ida_kernwin.msg("  Qt layer         : %s\n" % (P._QT_LAYER or "none"))
ida_kernwin.msg("  HexRays          : %s\n" % P._HAS_HEXRAYS)
ida_kernwin.msg("  IDB TIL          : %s\n" % (ida_typeinf.get_idati().name if ida_typeinf.get_idati() else "N/A"))
ida_kernwin.msg("  IDA 64-bit       : %s\n" % bool(ida_ida.inf_is_64bit()))
ida_kernwin.msg("  PT_SIL           : 0x%x\n" % (pt_sil or 0))
ida_kernwin.msg("  PT_TYP           : 0x%x\n" % (pt_typ or 0))
ida_kernwin.msg("  NTF_SYMM         : 0x%x\n" % (getattr(ida_typeinf, "NTF_SYMM", 0)))
ida_kernwin.msg("  Indirect CALLs   : %d\n" % len(indirect_eas))

_summary()