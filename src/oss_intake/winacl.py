"""Who can write to a folder on Windows, read from its security descriptor.

The descriptor is read with the Win32 API (read_sddl) as SDDL text, and the text is judged here in plain Python
(write_reason), so the judgement can be tested on any system. The judgement leans to "others can write": a deny
entry is not taken into account, an allow entry for any account other than the user, SYSTEM, the Administrators
group or TrustedInstaller counts, and a right it does not know counts as every right.
"""
from __future__ import annotations

import re
import sys
from collections.abc import Callable

SYSTEM, ADMINISTRATORS = "S-1-5-18", "S-1-5-32-544"
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_ALIASES = {"SY": SYSTEM, "BA": ADMINISTRATORS, "WD": "S-1-1-0", "AU": "S-1-5-11", "BU": "S-1-5-32-545",
            "IU": "S-1-5-4", "CO": "S-1-3-0", "OW": "S-1-3-4", "AN": "S-1-5-7", "BG": "S-1-5-32-546",
            "PU": "S-1-5-32-547", "NS": "S-1-5-20", "LS": "S-1-5-19"}
_NAMES = {"S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users", "S-1-5-32-545": "Users",
          "S-1-5-4": "Interactive users", "S-1-5-7": "Anonymous", "S-1-5-32-546": "Guests",
          "S-1-5-32-547": "Power Users", "S-1-5-20": "Network Service", "S-1-5-19": "Local Service"}
# CREATOR OWNER only matters in an inherit-only entry, and OWNER RIGHTS gives the owner, who is checked.
_NOT_AN_ACCOUNT = {"S-1-3-0", "S-1-3-4"}
_ALLOW_TYPES = {"A", "OA", "XA", "ZA"}

_RIGHTS = {"GA": 0x10000000, "GX": 0x20000000, "GW": 0x40000000, "GR": 0x80000000, "SD": 0x10000, "RC": 0x20000,
           "WD": 0x40000, "WO": 0x80000, "CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "RP": 0x10, "WP": 0x20,
           "DT": 0x40, "LO": 0x80, "CR": 0x100, "FA": 0x1F01FF, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200A0}
_ADD_FILE, _ADD_SUBFOLDER, _DELETE_CHILD = 0x2, 0x4, 0x40
_DELETE, _WRITE_DAC, _WRITE_OWNER, _GENERIC_ALL, _GENERIC_WRITE = 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000
# Rights over the folder itself that let someone put an entry in it, or replace or re-permission it.
FOLDER_WRITE = (_ADD_FILE | _ADD_SUBFOLDER | _DELETE_CHILD | _DELETE | _WRITE_DAC | _WRITE_OWNER | _GENERIC_ALL
                | _GENERIC_WRITE)
# Rights over a folder above it that let someone move the folder below away and put their own in its place.
PARENT_WRITE = _DELETE_CHILD | _DELETE | _WRITE_DAC | _WRITE_OWNER | _GENERIC_ALL


class SddlError(ValueError):
    """The descriptor text could not be read."""


def _sid(text: str, resolve: Callable[[str], str] | None = None) -> str:
    """A SID as S-1-... text. Short names this module does not know, some of them relative to the machine or
    domain (LA, the built-in Administrator; DA, Domain Admins), are resolved by Windows when resolve is given."""
    if text in _ALIASES:
        return _ALIASES[text]
    if resolve is not None and not text.startswith("S-1-"):
        try:
            return resolve(text)
        except OSError:
            pass
    return text


def _rights(text: str) -> int:
    if text.lower().startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            raise SddlError(f"rights {text!r}") from None
    if text.isdigit():
        return int(text)
    if len(text) % 2:
        raise SddlError(f"rights {text!r}")
    return sum(_RIGHTS.get(text[i:i + 2], 0xFFFFFFFF) for i in range(0, len(text), 2))


def _aces(text: str) -> list[list[str]]:
    """The entries of a DACL's text, '(A;OICI;FA;;;SY)(...)', each split at its top-level semicolons."""
    out, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
            if depth == 1:
                start = i + 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                out.append(text[start:i].split(";", 6))
            elif depth < 0:
                raise SddlError("unbalanced parentheses")
        elif depth == 0:
            raise SddlError(f"unexpected {ch!r} between entries")
    if depth:
        raise SddlError("unbalanced parentheses")
    return out


def parse(sddl: str, resolve: Callable[[str], str] | None = None
          ) -> tuple[str | None, list[tuple[str, str, int, str]] | None]:
    """(owner SID, [(type, flags, rights, SID)]) from 'O:...D:...'. The list is None for a NULL DACL (no access
    control: everyone has every right)."""
    m = re.fullmatch(r"(?:O:(S-1-[0-9-]+|[A-Z]{2}))?(?:G:(?:S-1-[0-9-]+|[A-Z]{2}))?(?:D:([A-Z_]*)(.*))?", sddl.strip(),
                     re.S)
    if not m or m.group(2) is None and m.group(3) is None:
        raise SddlError("no DACL")
    if "NO_ACCESS_CONTROL" in (m.group(2) or ""):
        return (_sid(m.group(1), resolve) if m.group(1) else None), None
    aces = []
    for parts in _aces(m.group(3) or ""):
        if len(parts) < 6:
            raise SddlError(f"entry {';'.join(parts)!r}")
        aces.append((parts[0], parts[1], _rights(parts[2]), _sid(parts[5], resolve)))
    return (_sid(m.group(1), resolve) if m.group(1) else None), aces


def name(sid: str) -> str:
    return _NAMES.get(sid, sid)


def write_reason(sddl: str, user_sid: str, mask: int, inherited: bool = False,
                 resolve: Callable[[str], str] | None = None) -> str | None:
    """Who other than the user and the system accounts holds one of the rights in mask, or owns the folder;
    None when no one does. With inherited, entries that only apply to what is made inside the folder count too
    (for the cache folder itself, whose entries and subfolders inherit them)."""
    trusted = {user_sid, SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER}
    owner, aces = parse(sddl, resolve)
    if owner is not None and owner not in trusted:
        return f"belongs to another account ({name(owner)})"
    if aces is None:
        return "has no access control, so everyone can write to it"
    others = []
    for kind, flags, rights, sid in aces:
        pairs = re.findall("..", flags)
        # An inherit-only entry applies to what is made inside, not to the folder itself.
        applies = "IO" not in pairs or (inherited and ("OI" in pairs or "CI" in pairs))
        if kind in _ALLOW_TYPES and applies and rights & mask and sid not in trusted | _NOT_AN_ACCOUNT:
            if name(sid) not in others:
                others.append(name(sid))
    return f"can be written by other users ({', '.join(others)})" if others else None


def read_sddl(path: str) -> str:
    """The folder's owner and DACL as SDDL text, read with the Win32 API. OSError when it cannot be read."""
    if sys.platform != "win32":
        raise OSError("Windows security descriptors can only be read on Windows")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes, kernel32.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    get_info = advapi32.GetNamedSecurityInfoW
    vp = ctypes.POINTER(ctypes.c_void_p)
    get_info.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, vp, vp, vp, vp, vp]
    get_info.restype = wintypes.DWORD
    to_text = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
    to_text.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                        ctypes.POINTER(wintypes.ULONG)]
    to_text.restype = wintypes.BOOL
    owner_and_dacl, se_file_object, sddl_revision_1 = 0x1 | 0x4, 1, 1
    sd = ctypes.c_void_p()
    err = get_info(path, se_file_object, owner_and_dacl, None, None, None, None, ctypes.byref(sd))
    if err:
        raise OSError(err, ctypes.FormatError(err))
    try:
        text = ctypes.c_void_p()
        if not to_text(sd, sddl_revision_1, owner_and_dacl, ctypes.byref(text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(text.value or 0)
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.LocalFree(sd)


def user_sid() -> str:
    """This process's user SID as text (S-1-5-21-...). OSError when it cannot be read."""
    if sys.platform != "win32":
        raise OSError("Windows accounts can only be read on Windows")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.argtypes, kernel32.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    token_query, token_user = 0x8, 1
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), token_query, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, token_user, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, token_user, buf, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]  # TOKEN_USER starts with the SID pointer
        text = ctypes.c_void_p()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(text.value or 0)
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.CloseHandle(token)


def resolve_alias(alias: str) -> str:
    """A SDDL short name (LA, DA, ...) as S-1-... text, as Windows resolves it. OSError when it cannot."""
    if sys.platform != "win32":
        raise OSError("SDDL short names can only be resolved on Windows")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes, kernel32.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    sid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(alias, ctypes.byref(sid)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        text = ctypes.c_void_p()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(text.value or 0)
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.LocalFree(sid)
