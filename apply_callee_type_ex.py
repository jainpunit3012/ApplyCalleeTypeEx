# Copyright (C) 2019 Mandiant, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# -----------------------------------------------------------------------
# Derivative work of the original Mandiant FLARE apply_callee_type plugin.
# Modifications:
#   - Single self-contained file; no flare package dependency
#   - Compatible with IDA Pro 8.x through 9.3+ (no legacy shims)
#   - Replaced all IDA 9.0 removed APIs (cvar.idati, choose_named_type2, etc.)
#   - Right-click context menu in disassembly and pseudocode views
#   - Multi-line prototype editor with live preprocessing preview
#   - Robust preprocessing: MSDN, ntdoc, SAL, __declspec, extern "C"
#   - Pseudocode EA resolution with get_screen_ea() fallback
#
# Ported by: Jiří Vinopal
#   X:      https://x.com/vinopaljiri
#   GitHub: https://github.com/Dump-GUY
# -----------------------------------------------------------------------

import re
import traceback

import idc
import idaapi
import ida_kernwin
import ida_typeinf
import ida_ua
import ida_idp
import ida_nalt

# IDA 9.2+ ships PySide6 (Qt6); earlier builds use PyQt5 (Qt5).
# Always try PySide6 first to avoid the PyQt5 shim confirmation popup on 9.2+.
_HAS_QT   = False
_QT_LAYER = None
try:
    from PySide6 import QtWidgets, QtCore
    _HAS_QT, _QT_LAYER = True, "pyside6"
except ImportError:
    try:
        from PyQt5 import QtWidgets, QtCore
        _HAS_QT, _QT_LAYER = True, "pyqt5"
    except ImportError:
        pass

try:
    import ida_hexrays
    _HAS_HEXRAYS = True
except ImportError:
    _HAS_HEXRAYS = False

# ── Constants ─────────────────────────────────────────────────────────────────

PLUGIN_NAME    = "ApplyCalleeTypeEx"
PLUGIN_COMMENT = "Apply callee type to indirect call location"
PLUGIN_HELP    = "Place cursor on an indirect CALL and press Shift+A."
ACTION_NAME    = "dump-guy:apply_callee_type_ex"
ACTION_LABEL   = "ApplyCalleeTypeEx"
ACTION_HOTKEY  = "Shift+A"
MENU_PATH      = "Edit/Operand type/"


def _msg(text):
    ida_kernwin.msg("[%s] %s\n" % (PLUGIN_NAME, text))

# ── Prototype preprocessor ────────────────────────────────────────────────────
#
# Strips/maps all constructs that parse_decl() cannot handle.
# Accepts input from: MSDN web, ntdoc, Windows SDK headers, ReactOS/Wine source.

_STRIP_WORDS = [
    "NTSYSAPI", "NTHALAPI", "NTKERNELAPI", "NTKRNLVISTAAPI",
    "WINBASEAPI", "WINADVAPI", "WINUSERAPI", "WINGDIAPI",
    "WINCRYPT32API", "WINSCARDAPI", "WINSPOOLAPI", "WINAPI_INLINE",
    "DECLSPEC_NORETURN", "DECLSPEC_NOINLINE", "DECLSPEC_DEPRECATED",
    "DECLSPEC_IMPORT", "DECLSPEC_EXPORT",
    "FORCEINLINE", "__forceinline", "__inline",
]

_CC_MAP = {
    "NTAPI": "__stdcall", "WINAPI": "__stdcall", "CALLBACK": "__stdcall",
    "APIENTRY": "__stdcall", "PASCAL": "__stdcall",
    "NTFASTCALL": "__fastcall", "FASTCALL": "__fastcall",
    "CDECL": "__cdecl", "WINAPIV": "__cdecl",
}

_SAL_KEYWORDS = [
    "_In_", "_Out_", "_Inout_", "_In_opt_", "_Out_opt_", "_Inout_opt_",
    "_In_reads_", "_In_reads_bytes_", "_In_reads_opt_",
    "_Out_writes_", "_Out_writes_bytes_", "_Out_writes_opt_",
    "_Inout_updates_", "_Inout_updates_bytes_",
    "_Outptr_", "_Outptr_opt_", "_Outptr_result_maybenull_",
    "_COM_Outptr_", "_COM_Outptr_opt_", "_Deref_out_", "_Deref_out_opt_",
    "_Reserved_", "_Success_", "_Check_return_", "_Must_inspect_result_",
    "_Post_maybez_", "_Null_terminated_", "_NullNull_terminated_",
    "OPTIONAL",
]

_RE_BRACKET = re.compile(
    r'\[\s*(?:in|out|in\s*,\s*out|in\s*,\s*optional|out\s*,\s*optional'
    r'|annotation|retval|unique|range|size_is|length_is|switch_type|switch_is'
    r'|iid_is|string|ptr|ref|ignore|optional|source|defaultvalue|lcid'
    r'|helpstring|helpcontext|hidden|id|propget|propput|propputref'
    r'|readonly|restricted|vararg)[^\]]*\]',
    re.IGNORECASE
)
_SAL_ARGS_RE = re.compile(
    r'(?<![A-Za-z0-9_])(?:' +
    '|'.join(re.escape(k.rstrip('_')) + r'_\([^)]*\)'
             for k in _SAL_KEYWORDS if k.endswith('_')) + r')',
    re.IGNORECASE
)
_SAL_RE           = re.compile(r'(?<![A-Za-z0-9_])(' + '|'.join(re.escape(k) for k in _SAL_KEYWORDS) + r')(?![A-Za-z0-9_])')
_RE_DECLSPEC      = re.compile(r'__declspec\s*\(\s*[^)]*\)', re.IGNORECASE)
_RE_DECLSPEC_MACRO= re.compile(r'DECLSPEC_ALIGN\s*\(\s*\d+\s*\)', re.IGNORECASE)
_RE_EXTERN_C      = re.compile(r'extern\s+"C"\s*\{?', re.IGNORECASE)
_RE_EXTERN        = re.compile(r'(?<![A-Za-z0-9_])extern(?![A-Za-z0-9_])')
_RE_STATIC        = re.compile(r'(?<![A-Za-z0-9_])static(?![A-Za-z0-9_])')
_RE_INLINE        = re.compile(r'(?<![A-Za-z0-9_])inline(?![A-Za-z0-9_])')
_RE_CLOSING_BRACE = re.compile(r'\}\s*;?\s*$')
_RE_CC            = re.compile(r'(?<![A-Za-z0-9_])(' + '|'.join(re.escape(k) for k in _CC_MAP) + r')(?![A-Za-z0-9_])')
_RE_STRIP         = re.compile(r'(?<![A-Za-z0-9_])(' + '|'.join(re.escape(w) for w in _STRIP_WORDS) + r')(?![A-Za-z0-9_])')


def _preprocess_prototype(decl):
    """Normalise a raw C prototype into a form parse_decl() accepts."""
    if not decl:
        return ""
    decl = re.sub(r'[\r\n\t]+', ' ', decl)
    decl = re.sub(r' {2,}', ' ', decl).strip()
    if not decl:
        return ""
    decl = _RE_EXTERN_C.sub('', decl)
    decl = _RE_DECLSPEC.sub('', decl)
    decl = _RE_DECLSPEC_MACRO.sub('', decl)
    decl = _RE_STRIP.sub('', decl)
    decl = _RE_INLINE.sub('', decl)
    decl = _RE_STATIC.sub('', decl)
    decl = _RE_EXTERN.sub('', decl)
    decl = _RE_CC.sub(lambda m: _CC_MAP[m.group(1)], decl)
    decl = _RE_BRACKET.sub('', decl)
    decl = _SAL_ARGS_RE.sub('', decl)
    decl = _SAL_RE.sub('', decl)
    decl = re.sub(r' {2,}', ' ', decl).strip()
    decl = _RE_CLOSING_BRACE.sub('', decl).strip()
    # VOID is a Windows typedef for void; parse_decl needs lowercase.
    decl = re.sub(r'(?<![A-Za-z0-9_])VOID(?![A-Za-z0-9_])', 'void', decl)
    return decl.rstrip(';').rstrip() + ';'


# ── Type parsing ──────────────────────────────────────────────────────────────

def _resolve_to_func_type(tif):
    """Return tif if it is a func or funcptr, otherwise None."""
    if tif.is_func() or tif.is_funcptr():
        return tif
    return None


def _parse_preprocessed(cleaned):
    """
    Parse an already-preprocessed prototype string into a tinfo_t.
    Always silent (PT_SIL) so IDA never emits "Bad declaration" to the console.
    Returns tinfo_t (func or funcptr) on success, None on failure.
    """
    PT_SIL = (getattr(ida_typeinf, "PT_SIL", None) or
              getattr(ida_typeinf, "PT_SILENT", None) or 0x1)
    PT_TYP = getattr(ida_typeinf, "PT_TYP", 0x4)
    for flags in (PT_TYP | PT_SIL, PT_SIL):
        tif = ida_typeinf.tinfo_t()
        if ida_typeinf.parse_decl(tif, None, cleaned, flags) is None:
            continue
        resolved = _resolve_to_func_type(tif)
        if resolved is not None:
            return resolved
    return None


def parse_type_from_string(type_str):
    """Preprocess + parse a raw prototype string. Returns tinfo_t or None."""
    if not type_str:
        return None
    cleaned = _preprocess_prototype(type_str)
    if not cleaned or cleaned == ";":
        return None
    return _parse_preprocessed(cleaned)


# ── TIL type retrieval ────────────────────────────────────────────────────────

def _get_named_type_and_deserialize(til, name):
    """
    Retrieve a named type via module-level get_named_type() + deserialize().
    Correctly reaches types in external base TILs (e.g. MS SDK).
    Returns tinfo_t on success, None on failure.
    """
    try:
        t = ida_typeinf.get_named_type(til, name, ida_typeinf.NTF_SYMM)
        if t is None or t[1] is None:
            return None
        tif = ida_typeinf.tinfo_t()
        return tif if tif.deserialize(til, t[1], t[2]) else None
    except Exception:
        return None


def choose_standard_type():
    """Open TIL browser; return selected tinfo_t or None if cancelled/failed."""
    try:
        sym = ida_typeinf.til_symbol_t()
        if not ida_typeinf.choose_named_type(
                sym, ida_typeinf.get_idati(), "Choose Type to Apply",
                ida_typeinf.NTF_SYMM, None):
            return None

        tif = _get_named_type_and_deserialize(sym.til, sym.name)
        if tif is not None:
            return tif

        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(sym.til, sym.name):
            return tif

        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(ida_typeinf.get_idati(), sym.name):
            return tif

        try:
            idc.import_type(ida_typeinf.get_idati(), -1, sym.name)
            tif = ida_typeinf.tinfo_t()
            if tif.get_named_type(ida_typeinf.get_idati(), sym.name):
                return tif
        except Exception:
            pass

        _msg("Could not retrieve '%s' — import it via View → Local Types first." % sym.name)
        return None

    except Exception as exc:
        _msg("Standard type browser failed (%s) — falling back to manual entry." % exc)
        raw = ida_kernwin.ask_str("", ida_kernwin.HIST_TYPE, "Enter Function Prototype:")
        return parse_type_from_string(raw) if raw else None


def choose_local_type():
    """Open IDB local types browser; return selected tinfo_t or None."""
    try:
        ordinal = ida_typeinf.choose_local_tinfo(
            ida_typeinf.get_idati(), "Choose Local Type to Apply", None, 0, None)
        if not ordinal:
            return None
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(ida_typeinf.get_idati(), ordinal):
            return tif
        _msg("Could not deserialize local type at ordinal %d." % ordinal)
        return None
    except Exception as exc:
        _msg("Local type browser failed (%s) — falling back to manual entry." % exc)
        raw = ida_kernwin.ask_str("", ida_kernwin.HIST_TYPE, "Enter Function Prototype:")
        return parse_type_from_string(raw) if raw else None


# ── Qt dialogs ────────────────────────────────────────────────────────────────

_MANUAL_HINT = (
    "Accepts any real-world format — annotations stripped automatically.\n\n"
    "Examples:\n"
    "  UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow);\n"
    "  typedef UINT (WINAPI *PWINEXEC)(LPCSTR, UINT);\n"
    "  UINT (__stdcall *)(LPCSTR, UINT)\n\n"
    "  NTSYSAPI\n"
    "  NTSTATUS\n"
    "  NTAPI\n"
    "  LdrGetProcedureAddress(\n"
    "      _In_     PVOID          DllHandle,\n"
    "      _In_opt_ PCANSI_STRING  ProcedureName,\n"
    "      _In_opt_ ULONG          ProcedureNumber,\n"
    "      _Out_    PVOID         *ProcedureAddress\n"
    "  );"
)


class _TypeSourceDialog(QtWidgets.QDialog):
    CHOICE_MANUAL   = 1
    CHOICE_STANDARD = 2
    CHOICE_LOCAL    = 3

    def __init__(self, ea, parent=None):
        super().__init__(parent)
        self.choice = None
        self.setWindowTitle("ApplyCalleeTypeEx — 0x%X" % ea)
        self.setMinimumWidth(360)
        try:
            self.setWindowFlags(self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)
        except Exception:
            pass

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(QtWidgets.QLabel("Select prototype source for call at 0x%X:" % ea))
        layout.addSpacing(6)
        for text, tip, choice in (
            ("Enter Manually…",         "Open multi-line prototype editor",                    self.CHOICE_MANUAL),
            ("Standard Type  (TIL)",     "Browse loaded TIL (type library) types",              self.CHOICE_STANDARD),
            ("Local Type  (IDB)",        "Browse types defined in this IDB",                    self.CHOICE_LOCAL),
        ):
            btn = QtWidgets.QPushButton(text)
            btn.setToolTip(tip)
            btn.clicked.connect(lambda _=False, c=choice: self._pick(c))
            layout.addWidget(btn)
        layout.addSpacing(8)
        cancel = QtWidgets.QPushButton("Cancel")
        cancel.setDefault(True)
        cancel.clicked.connect(self.reject)
        layout.addWidget(cancel)

    def _pick(self, choice):
        self.choice = choice
        self.accept()


class _ManualTypeDialog(QtWidgets.QDialog):

    def __init__(self, ea, parent=None):
        super().__init__(parent)
        self.result_text = ""
        self.setWindowTitle("ApplyCalleeTypeEx — Enter Prototype (0x%X)" % ea)
        self.setMinimumSize(640, 500)

        root = QtWidgets.QVBoxLayout(self)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        root.addWidget(splitter, 1)

        top = QtWidgets.QWidget()
        tl  = QtWidgets.QVBoxLayout(top)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.addWidget(QtWidgets.QLabel("Input:"))
        self._editor = QtWidgets.QPlainTextEdit()
        self._editor.setPlaceholderText(_MANUAL_HINT)
        self._editor.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self._set_mono(self._editor)
        tl.addWidget(self._editor)
        splitter.addWidget(top)

        bot = QtWidgets.QWidget()
        bl  = QtWidgets.QVBoxLayout(bot)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.addWidget(QtWidgets.QLabel("Preprocessed  (sent to parse_decl):"))
        self._preview = QtWidgets.QPlainTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setMaximumHeight(72)
        self._set_mono(self._preview)
        bl.addWidget(self._preview)
        splitter.addWidget(bot)
        splitter.setSizes([360, 72])

        row = QtWidgets.QHBoxLayout()
        self._apply_btn = QtWidgets.QPushButton("Apply")
        self._apply_btn.setEnabled(False)
        self._apply_btn.setDefault(True)
        self._apply_btn.clicked.connect(self._on_apply)
        cancel = QtWidgets.QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        row.addStretch()
        row.addWidget(self._apply_btn)
        row.addWidget(cancel)
        root.addLayout(row)

        self._editor.textChanged.connect(self._update)

    @staticmethod
    def _set_mono(w):
        try:
            from PySide6.QtGui import QFontDatabase
            w.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        except Exception:
            try:
                from PyQt5.QtGui import QFontDatabase
                w.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
            except Exception:
                pass

    def _update(self):
        processed = _preprocess_prototype(self._editor.toPlainText())
        self._preview.setPlainText(processed)
        self._apply_btn.setEnabled(bool(processed.strip().rstrip(';')))

    def _on_apply(self):
        self.result_text = _preprocess_prototype(self._editor.toPlainText())
        self.accept()


# ── User interaction ──────────────────────────────────────────────────────────

def get_type_from_user(ea):
    """Show type-source dialog and return tinfo_t from the selected path, or None."""
    if _HAS_QT:
        dlg = _TypeSourceDialog(ea)
        old = idaapi.set_script_timeout(0)
        try:
            ok = bool(dlg.exec_())
        finally:
            idaapi.set_script_timeout(old)
        if not ok or dlg.choice is None:
            return None
        choice = dlg.choice
    else:
        # ask_buttons: 1=first, 0=second, -1=third/cancel
        raw = ida_kernwin.ask_buttons(
            "Enter Manually", "Standard Type", "Local Type", -1,
            "ApplyCalleeTypeEx — Select Prototype Source (0x%X):" % ea)
        if raw == 1:
            choice = _TypeSourceDialog.CHOICE_MANUAL
        elif raw == 0:
            choice = _TypeSourceDialog.CHOICE_STANDARD
        elif raw == -1:
            # -1 is returned for both the Local Type button AND Escape/cancel;
            # indistinguishable via ask_buttons, so treat as cancel.
            return None
        else:
            return None

    if choice == _TypeSourceDialog.CHOICE_MANUAL:
        return _get_manual_type(ea)
    elif choice == _TypeSourceDialog.CHOICE_STANDARD:
        return choose_standard_type()
    else:
        return choose_local_type()


def _get_manual_type(ea):
    """Open multi-line editor (or ask_str fallback) and return parsed tinfo_t."""
    if _HAS_QT:
        dlg = _ManualTypeDialog(ea)
        old = idaapi.set_script_timeout(0)
        try:
            ok = bool(dlg.exec_())
        finally:
            idaapi.set_script_timeout(old)
        if not ok or not dlg.result_text.strip().rstrip(';'):
            return None
        tif = _parse_preprocessed(dlg.result_text)
        if tif is None:
            _msg("Could not parse prototype — check syntax and try again.")
        return tif
    else:
        raw = ida_kernwin.ask_str(
            "", ida_kernwin.HIST_TYPE,
            "Enter Prototype (MSDN/SAL annotations stripped automatically):")
        if not raw:
            return None
        tif = parse_type_from_string(raw)
        if tif is None:
            _msg("Could not parse prototype — check syntax and try again.")
        return tif


# ── Core apply logic ──────────────────────────────────────────────────────────

def apply_type_to_call(ea, tif):
    """
    Apply tif to the indirect CALL at ea via apply_callee_tinfo().
    Returns True on success, False otherwise.
    """
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea):
        _msg("No instruction at 0x%X." % ea)
        return False
    if not ida_idp.is_call_insn(insn):
        _msg("0x%X is not a CALL instruction." % ea)
        return False
    if idc.get_operand_type(ea, 0) in (idc.o_near, idc.o_far):
        _msg("Direct CALL at 0x%X — IDA resolves direct calls automatically." % ea)
        return False

    apply_tif = tif
    if tif.is_func():
        ptr = ida_typeinf.tinfo_t()
        ptr.create_ptr(tif)
        apply_tif = ptr

    if not ida_typeinf.apply_callee_tinfo(ea, apply_tif):
        _msg("apply_callee_tinfo() failed at 0x%X." % ea)
        return False

    try:
        ida_nalt.set_op_tinfo(ea, 0, apply_tif)
    except Exception:
        pass

    return True


# ── Action handler ────────────────────────────────────────────────────────────

class ApplyCalleeTypeHandler(ida_kernwin.action_handler_t):

    def activate(self, ctx):
        # IDA maps the pseudocode cursor to the underlying instruction EA.
        # If the citem carries no address (lvar reference), get_screen_ea() is
        # the correct fallback — identical to what the original FLARE plugin used.
        ea = ida_kernwin.get_screen_ea()
        if _HAS_HEXRAYS and ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            try:
                vdui = ida_hexrays.get_widget_vdui(ctx.widget)
                if vdui and vdui.item.is_citem():
                    item_ea = vdui.item.it.ea
                    if item_ea != idaapi.BADADDR:
                        ea = item_ea
            except Exception:
                pass

        tif = get_type_from_user(ea)
        if tif is None:
            return 1

        type_str = ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE, tif, "", "")
        if apply_type_to_call(ea, tif):
            _msg("Applied '%s' at 0x%X." % (type_str, ea))
        else:
            _msg("Failed to apply '%s' at 0x%X." % (type_str, ea))
        return 1

    def update(self, ctx):
        if ctx.widget_type in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


# ── UI hooks ──────────────────────────────────────────────────────────────────

class ApplyCalleeTypeHooks(ida_kernwin.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) in (
                ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME, None)


# ── Plugin ────────────────────────────────────────────────────────────────────

class ApplyCalleeTypePlugin(idaapi.plugin_t):
    """
    Apply a known function prototype to an indirect CALL instruction.
    Ported from Mandiant FLARE apply_callee_type. IDA Pro 8.x → 9.3+.
    """
    flags         = idaapi.PLUGIN_KEEP
    comment       = PLUGIN_COMMENT
    help          = PLUGIN_HELP
    wanted_name   = PLUGIN_NAME
    wanted_hotkey = ""  # registered via action system

    def init(self):
        desc = ida_kernwin.action_desc_t(
            ACTION_NAME, ACTION_LABEL, ApplyCalleeTypeHandler(),
            ACTION_HOTKEY, PLUGIN_COMMENT, -1)
        if not ida_kernwin.register_action(desc):
            _msg("Failed to register action — plugin skipped.")
            return idaapi.PLUGIN_SKIP
        ida_kernwin.attach_action_to_menu(MENU_PATH, ACTION_NAME, ida_kernwin.SETMENU_APP)
        self._hooks = ApplyCalleeTypeHooks()
        self._hooks.hook()
        _msg("Ready  |  Shift+A  |  right-click: disasm + pseudocode  |  Qt: %s"
             % (_QT_LAYER or "none"))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        _msg("Place cursor on an indirect CALL and press Shift+A.")

    def term(self):
        try:
            ida_kernwin.detach_action_from_menu(MENU_PATH, ACTION_NAME)
        except Exception:
            pass
        ida_kernwin.unregister_action(ACTION_NAME)
        if hasattr(self, "_hooks"):
            self._hooks.unhook()


def PLUGIN_ENTRY():
    try:
        return ApplyCalleeTypePlugin()
    except Exception as exc:
        ida_kernwin.msg("[%s] PLUGIN_ENTRY failed: %s\n%s"
                        % (PLUGIN_NAME, exc, traceback.format_exc()))
        raise