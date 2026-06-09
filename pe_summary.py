# pe_summary.py
# Malware PE triage summary using pefile.
# Intended for first-stage static triage, not full malware analysis.
# Dependency: pip install pefile
# Usage:
#   python pe_summary_improved_v6.py sample.exe
#   python pe_summary_improved_v6.py sample.exe -o report.txt
#   python pe_summary_improved_v6.py sample.exe --json
#   python pe_summary_improved_v6.py sample.exe --json --json-output details.json
#   python pe_summary_improved_v6.py sample.exe --print

import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import pefile


SUSPICIOUS_SECTION_NAMES = {
    ".upx", "upx0", "upx1",
    ".aspack", ".adata", ".packed",
    ".themida", ".vmp0", ".vmp1",
    ".enigma", ".petite",
    ".l1", ".l2", ".rmnet"
}

COMMON_SECTION_NAMES = {
    ".text", ".rdata", ".data", ".pdata", ".xdata", ".bss", ".idata", ".edata",
    ".rsrc", ".reloc", ".tls", ".debug", ".CRT", ".code", "CODE", "DATA", "BSS"
}

LOW_SIGNAL_RESOURCE_TYPES = {
    "RT_ICON", "RT_GROUP_ICON", "RT_CURSOR", "RT_GROUP_CURSOR", "RT_VERSION", "RT_MANIFEST"
}

MAX_MAGIC_SCAN_BYTES = 32 * 1024 * 1024

NOISY_NETWORK_SUFFIXES = (
    "digicert.com",
    "sectigo.com",
    "comodoca.com",
    "comodoca.net",
    "usertrust.com",
    "verisign.com",
    "thawte.com",
    "globalsign.com",
    "entrust.net",
    "entrust.com",
    "geotrust.com",
    "certum.pl",
    "pki.goog",
    "msocsp.com"
)

NOISY_NETWORK_EXACT = {
    "crl.microsoft.com",
    "www.microsoft.com",
    "mscrl.microsoft.com",
    "ocsp.msocsp.com",
    "oneocsp.microsoft.com",
    "ocsp.digicert.com",
    "crl3.digicert.com",
    "crl4.digicert.com",
    "ocsp.sectigo.com",
    "crt.sectigo.com"
}

MAGIC_SIGNATURES = [
    (b"MZ", "PE/MZ"),
    (b"\x7fELF", "ELF"),
    (b"PK\x03\x04", "ZIP"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"\x1f\x8b", "GZIP"),
    (b"MSCF", "CAB"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE/CFB"),
    (b"%PDF", "PDF"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"{", "Possible JSON/text")
]

EMBEDDED_MAGIC_SIGNATURES = [
    (signature, name) for signature, name in MAGIC_SIGNATURES
    if name != "Possible JSON/text"
]

STRING_PATTERNS = {
    "urls": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domains": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
    "emails": re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"),
    "registry_paths": re.compile(r"\b(?:HKCU|HKLM|HKCR|HKU|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|HKEY_USERS)\\[^\x00\r\n\"']+", re.IGNORECASE),
    "windows_paths": re.compile(r"\b[A-Za-z]:\\[^\x00\r\n\"']+", re.IGNORECASE),
    "unc_paths": re.compile(r"\\\\[A-Za-z0-9_.-]+\\[^\x00\r\n\"']+", re.IGNORECASE),
    "named_pipes": re.compile(r"\\\\\.\\pipe\\[A-Za-z0-9_.\-/]+", re.IGNORECASE),
    "pdb_paths": re.compile(r"(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\)[^\x00\r\n\"']+\.pdb", re.IGNORECASE),
    "base64_like": re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
    "hex_like": re.compile(r"\b(?:[A-Fa-f0-9]{2}){20,}\b")
}

KEYWORD_CATEGORIES = {
    "execution_lolbins": [
        "powershell", "pwsh", "cmd.exe", "rundll32", "regsvr32", "mshta",
        "wscript", "cscript", "certutil", "bitsadmin", "schtasks",
        "wmic", "installutil", "msbuild", "reg.exe", "curl.exe", "msiexec"
    ],
    "anti_analysis": [
        "sandbox", "virtualbox", "vbox", "vmware", "qemu", "xen", "hyper-v",
        "wireshark", "procmon", "process monitor", "x64dbg", "x32dbg",
        "ida", "ollydbg", "debugger", "fiddler", "frida", "analysis"
    ],
    "persistence": [
        "\\currentversion\\run", "\\currentversion\\runonce",
        "startup", "createservice", "startservice", "schtasks",
        "task scheduler", "wmi", "winlogon", "appinit_dlls"
    ],
    "credential_browser": [
        "password", "passwd", "cookie", "cookies", "login data",
        "local state", "discord", "telegram", "wallet", "metamask",
        "chrome", "edge", "firefox", "brave", "opera", "token"
    ],
    "crypto_encoding": [
        "aes", "rsa", "rc4", "xor", "base64", "cryptdecrypt",
        "bcryptdecrypt", "private key", "public key", "-----begin"
    ],
    "network_terms": [
        "user-agent", "content-type", "authorization", "bearer ",
        "websocket", "http_post", "http_get", "multipart/form-data"
    ]
}


# Anti-analysis string matching is intentionally regex-based instead of simple
# substring matching. Substring matching produced noisy hits such as ".idata",
# ".didat", "Friday", and PNG "IDAT" chunks because they contain "ida"/"frida".
ANTI_ANALYSIS_STRING_PATTERNS = [
    re.compile(r"(?<![a-z0-9])sandbox(?:ie)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])virtualbox(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])vbox(?:service|tray|guest|mouse|sf|video)?(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])vmware(?:tray|service|user|tools|checkvmx|guestd)?(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])qemu(?:-ga)?(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])xen(?:service|tools)?(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])hyper-v(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])wireshark(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])procmon(?:64)?(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])process monitor(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])x64dbg(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])x32dbg(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])ollydbg(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])fiddler(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])frida(?:[-_ ]?(?:server|agent|trace|ps|inject))?(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])ida(?:32|64)?(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])idaq(?:64)?(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])idaw(?:64)?(?:\.exe)?(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])ida pro(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])idapython(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"isdebuggerpresent", re.IGNORECASE),
    re.compile(r"checkremotedebuggerpresent", re.IGNORECASE),
    re.compile(r"ntqueryinformationprocess", re.IGNORECASE),
    re.compile(r"outputdebugstring[aw]?", re.IGNORECASE),
    re.compile(r"beingdebugged", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])debugger(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])anti[-_ ]analysis(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])anti[-_ ]debug(?:ging)?(?![a-z0-9])", re.IGNORECASE),
]


def anti_analysis_string_match(value):
    return any(pattern.search(value) for pattern in ANTI_ANALYSIS_STRING_PATTERNS)


def keyword_category_match(category, value, lowered, keywords):
    if category == "anti_analysis":
        return anti_analysis_string_match(value)

    return any(keyword.lower() in lowered for keyword in keywords)

API_CATEGORIES = {
    "process_memory": {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "VirtualFree",
        "HeapAlloc", "HeapCreate", "MapViewOfFile", "CreateFileMappingA", "CreateFileMappingW",
        "WriteProcessMemory", "ReadProcessMemory", "OpenProcess", "NtOpenProcess", "ZwOpenProcess",
        "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext",
        "GetThreadContext", "ResumeThread", "SuspendThread", "NtMapViewOfSection", "ZwMapViewOfSection",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "VirtualQuery", "VirtualQueryEx",
        "RtlMoveMemory", "RtlCopyMemory"
    },
    "execution": {
        "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW",
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress",
        "ExitProcess", "TerminateProcess", "CreateProcessInternalW", "CreateThread"
    },
    "process_discovery": {
        "CreateToolhelp32Snapshot", "Process32First", "Process32FirstW", "Process32Next", "Process32NextW",
        "Thread32First", "Thread32Next", "EnumProcesses", "EnumProcessModules", "EnumProcessModulesEx"
    },
    "network": {
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
        "InternetReadFile", "InternetWriteFile", "WinHttpOpen", "WinHttpConnect",
        "WinHttpOpenRequest", "WinHttpSendRequest", "WinHttpReceiveResponse", "WinHttpReadData", "WinHttpWriteData",
        "URLDownloadToFileA", "URLDownloadToFileW", "WSAStartup", "socket", "connect",
        "send", "recv", "bind", "listen", "accept", "gethostbyname", "getaddrinfo",
        "DnsQuery_A", "DnsQuery_W", "DnsQuery_UTF8", "WSASocketA", "WSASocketW", "InternetSetOptionA", "InternetSetOptionW"
    },
    "registry": {
        "RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyA", "RegCreateKeyW",
        "RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueA", "RegSetValueW",
        "RegSetValueExA", "RegSetValueExW", "RegQueryValueA", "RegQueryValueW",
        "RegQueryValueExA", "RegQueryValueExW", "RegDeleteValueA", "RegDeleteValueW",
        "RegDeleteKeyA", "RegDeleteKeyW", "RegDeleteKeyExA", "RegDeleteKeyExW"
    },
    "file_system": {
        "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "DeleteFileA", "DeleteFileW",
        "MoveFileA", "MoveFileW", "MoveFileExA", "MoveFileExW", "CopyFileA", "CopyFileW",
        "FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW",
        "GetTempPathA", "GetTempPathW", "GetTempFileNameA", "GetTempFileNameW",
        "SetFileAttributesA", "SetFileAttributesW", "GetFileAttributesA", "GetFileAttributesW"
    },
    "service": {
        "OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW",
        "OpenServiceA", "OpenServiceW", "StartServiceA", "StartServiceW",
        "DeleteService", "ControlService", "ChangeServiceConfigA", "ChangeServiceConfigW"
    },
    "crypto": {
        "CryptAcquireContextA", "CryptAcquireContextW", "CryptCreateHash", "CryptHashData",
        "CryptDeriveKey", "CryptDecrypt", "CryptEncrypt", "CryptGenRandom", "CryptUnprotectData",
        "BCryptOpenAlgorithmProvider", "BCryptGenerateSymmetricKey", "BCryptDecrypt",
        "BCryptEncrypt", "BCryptGenRandom"
    },
    "credential_access": {
        "CryptUnprotectData", "MiniDumpWriteDump", "CredEnumerateA", "CredEnumerateW", "CredReadA", "CredReadW",
        "VaultOpenVault", "VaultEnumerateVaults", "VaultEnumerateItems", "VaultGetItem"
    },
    "privilege_token": {
        "OpenProcessToken", "OpenThreadToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
        "DuplicateToken", "DuplicateTokenEx", "ImpersonateLoggedOnUser", "RevertToSelf"
    },
    "anti_analysis": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "OutputDebugStringW", "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
        "Sleep", "SleepEx", "SetUnhandledExceptionFilter"
    },
    "mutex": {
        "CreateMutexA", "CreateMutexW", "OpenMutexA", "OpenMutexW"
    },
    "lateral_admin": {
        "WNetAddConnection2A", "WNetAddConnection2W", "NetUserEnum", "NetShareEnum", "NetLocalGroupEnum",
        "ldap_init", "ldap_initA", "ldap_initW", "ldap_search_s", "ldap_search_sA", "ldap_search_sW"
    },
    "com_wmi": {
        "CoInitialize", "CoInitializeEx", "CoInitializeSecurity", "CoCreateInstance", "CoSetProxyBlanket"
    },
    "persistence_related": {
        "CreateServiceA", "CreateServiceW", "RegSetValueA", "RegSetValueW",
        "RegSetValueExA", "RegSetValueExW", "SHGetFolderPathA", "SHGetFolderPathW",
        "SHGetKnownFolderPath"
    }
}

API_COMBINATION_RULES = [
    {
        "id": "api_classic_remote_thread_injection",
        "title": "Classic remote-thread injection import pattern",
        "severity": "high",
        "confidence": "medium",
        "required": [
            ["OpenProcess", "NtOpenProcess", "ZwOpenProcess"],
            ["VirtualAllocEx"],
            ["WriteProcessMemory"],
            ["CreateRemoteThread", "NtCreateThreadEx"]
        ],
        "recommendation": "Inspect call sites around the injection-related imports."
    },
    {
        "id": "api_apc_or_thread_context_injection",
        "title": "APC/thread-context injection import pattern",
        "severity": "medium",
        "confidence": "medium",
        "required": [
            ["OpenProcess", "NtOpenProcess", "ZwOpenProcess"],
            ["VirtualAllocEx", "NtMapViewOfSection", "ZwMapViewOfSection"],
            ["WriteProcessMemory", "MapViewOfFile"],
            ["QueueUserAPC", "SetThreadContext"]
        ],
        "recommendation": "Check whether code writes into another process and redirects execution."
    },
    {
        "id": "api_process_hollowing_like",
        "title": "Process hollowing-like import pattern",
        "severity": "high",
        "confidence": "medium",
        "required": [
            ["CreateProcessA", "CreateProcessW"],
            ["NtUnmapViewOfSection", "ZwUnmapViewOfSection", "VirtualAllocEx"],
            ["WriteProcessMemory"],
            ["SetThreadContext", "ResumeThread"]
        ],
        "recommendation": "Check whether a suspended child process is created and overwritten."
    },
    {
        "id": "api_dynamic_resolution",
        "title": "Dynamic API resolution imports",
        "severity": "medium",
        "confidence": "medium",
        "required": [
            ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"],
            ["GetProcAddress"]
        ],
        "recommendation": "Run FLOSS and inspect resolved API-name strings."
    },
    {
        "id": "api_downloader_file_write",
        "title": "Downloader-like network and file-write imports",
        "severity": "medium",
        "confidence": "medium",
        "required": [
            ["InternetReadFile", "WinHttpReadData", "URLDownloadToFileA", "URLDownloadToFileW", "recv"],
            ["CreateFileA", "CreateFileW", "WriteFile"]
        ],
        "recommendation": "Look for URL/config strings and file-drop paths."
    },
    {
        "id": "api_downloader_execute",
        "title": "Downloader-like network and execution imports",
        "severity": "high",
        "confidence": "medium",
        "required": [
            ["InternetReadFile", "WinHttpReadData", "URLDownloadToFileA", "URLDownloadToFileW", "recv"],
            ["CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW", "WinExec"]
        ],
        "recommendation": "Check whether downloaded content is executed or staged."
    },
    {
        "id": "api_service_persistence",
        "title": "Service persistence import pattern",
        "severity": "medium",
        "confidence": "medium",
        "required": [
            ["OpenSCManagerA", "OpenSCManagerW"],
            ["CreateServiceA", "CreateServiceW", "ChangeServiceConfigA", "ChangeServiceConfigW"]
        ],
        "recommendation": "Inspect service name, binary path, and start type strings."
    },
    {
        "id": "api_registry_persistence",
        "title": "Registry persistence-capable imports",
        "severity": "medium",
        "confidence": "low",
        "required": [
            ["RegCreateKeyA", "RegCreateKeyW", "RegCreateKeyExA", "RegCreateKeyExW", "RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW"],
            ["RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW"]
        ],
        "recommendation": "Check for Run/RunOnce, Winlogon, AppInit_DLLs, or service-related registry paths."
    },
    {
        "id": "api_dpapi_credential_access",
        "title": "DPAPI credential-related import",
        "severity": "medium",
        "confidence": "medium",
        "required": [
            ["CryptUnprotectData"]
        ],
        "recommendation": "Check for browser, cookie, wallet, token, or credential-store strings."
    },
    {
        "id": "api_process_dumping",
        "title": "Process dumping import",
        "severity": "high",
        "confidence": "medium",
        "required": [
            ["MiniDumpWriteDump"]
        ],
        "recommendation": "Check whether LSASS or another sensitive process is targeted."
    },
    {
        "id": "api_privilege_adjustment",
        "title": "Privilege adjustment import pattern",
        "severity": "medium",
        "confidence": "medium",
        "required": [
            ["OpenProcessToken", "OpenThreadToken"],
            ["LookupPrivilegeValueA", "LookupPrivilegeValueW"],
            ["AdjustTokenPrivileges"]
        ],
        "recommendation": "Look for SeDebugPrivilege, SeBackupPrivilege, or similar privilege strings."
    },
    {
        "id": "api_anti_debugging",
        "title": "Anti-debugging or timing-related imports",
        "severity": "low",
        "confidence": "medium",
        "required": [
            ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW", "QueryPerformanceCounter"]
        ],
        "recommendation": "Keep anti-analysis in mind during debugging."
    },
    {
        "id": "api_admin_network_enum",
        "title": "Administrative network enumeration imports",
        "severity": "medium",
        "confidence": "medium",
        "required": [
            ["NetUserEnum", "NetShareEnum", "NetLocalGroupEnum", "WNetAddConnection2A", "WNetAddConnection2W", "ldap_init", "ldap_initA", "ldap_initW"]
        ],
        "recommendation": "Check whether the sample enumerates domain, share, or local account data."
    }
]


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def preview(value, length=140):
    value = str(value).replace("\r", "\\r").replace("\n", "\\n")

    if len(value) <= length:
        return value

    return value[:length] + "..."


def entropy(data):
    if not data:
        return 0.0

    counts = [0] * 256

    for b in data:
        counts[b] += 1

    result = 0.0
    size = len(data)

    for count in counts:
        if count:
            p = count / size
            result -= p * math.log2(p)

    return result


def safe_decode(value):
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode(errors="replace").rstrip("\x00")

    return str(value).rstrip("\x00")


def clean_section_name(value):
    name = safe_decode(value)

    if name is None:
        return ""

    return name.rstrip("\x00")


def timestamp_to_utc(timestamp):
    try:
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    except Exception:
        return "invalid"


def timestamp_notes(raw_ts):
    notes = []

    if raw_ts == 0:
        notes.append("Compile timestamp is zero")
        return notes

    try:
        dt = datetime.fromtimestamp(raw_ts, timezone.utc)
        now = datetime.now(timezone.utc)

        if dt.year < 2000:
            notes.append("Compile timestamp is before 2000")

        if dt > now:
            notes.append("Compile timestamp is in the future")

    except Exception:
        notes.append("Compile timestamp could not be parsed")

    return notes


def machine_type(value):
    mapping = {
        0x014c: "x86",
        0x8664: "x64",
        0x0200: "Intel Itanium",
        0x01c0: "ARM",
        0x01c4: "ARMv7",
        0xaa64: "ARM64"
    }

    return mapping.get(value, f"unknown/0x{value:04x}")


def subsystem_type(value):
    mapping = {
        1: "Native",
        2: "Windows GUI",
        3: "Windows Console",
        7: "POSIX Console",
        9: "Windows CE GUI",
        10: "EFI Application",
        11: "EFI Boot Service Driver",
        12: "EFI Runtime Driver",
        14: "Xbox"
    }

    return mapping.get(value, f"unknown/{value}")


def magic_hint(data):
    for sig, name in MAGIC_SIGNATURES:
        if data.startswith(sig):
            return name

    return None


def validate_embedded_pe(data, offset):
    if offset < 0 or offset + 0x40 > len(data):
        return {
            "valid": False,
            "reason": "MZ too close to end of data"
        }

    if data[offset:offset + 2] != b"MZ":
        return {
            "valid": False,
            "reason": "MZ signature not present at offset"
        }

    try:
        e_lfanew = int.from_bytes(data[offset + 0x3c:offset + 0x40], "little")
    except Exception:
        return {
            "valid": False,
            "reason": "could not read e_lfanew"
        }

    pe_offset = offset + e_lfanew

    if e_lfanew <= 0:
        return {
            "valid": False,
            "reason": "invalid e_lfanew"
        }

    if pe_offset + 4 > len(data):
        return {
            "valid": False,
            "reason": "PE header offset outside data"
        }

    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return {
            "valid": False,
            "reason": "MZ without valid PE header"
        }

    return {
        "valid": True,
        "e_lfanew": hex(e_lfanew),
        "pe_header_offset": hex(pe_offset)
    }


def find_magic_hits(data, limit=10, include_offset_zero=False):
    hits = []
    max_hits_per_signature = max(limit * 4, 16)

    for sig, name in EMBEDDED_MAGIC_SIGNATURES:
        start = 0
        hits_for_signature = 0

        while True:
            offset = data.find(sig, start)

            if offset == -1:
                break

            start = offset + 1

            if offset == 0 and not include_offset_zero:
                continue

            hit = {
                "offset": hex(offset),
                "offset_int": offset,
                "magic": name,
                "confidence": "medium"
            }

            if name == "PE/MZ":
                validation = validate_embedded_pe(data, offset)
                hit["pe_validation"] = validation

                if validation.get("valid"):
                    hit["confidence"] = "high"
                else:
                    hit["confidence"] = "low"
                    hit["note"] = validation.get("reason")

            hits.append(hit)
            hits_for_signature += 1

            if hits_for_signature >= max_hits_per_signature:
                break

    hits = sorted(
        hits,
        key=lambda item: (
            confidence_rank(item.get("confidence", "low")),
            item.get("offset_int", 0)
        )
    )

    for hit in hits:
        hit.pop("offset_int", None)

    return hits[:limit]


def has_valid_embedded_pe(magic_hits):
    return any(
        hit.get("magic") == "PE/MZ" and hit.get("pe_validation", {}).get("valid")
        for hit in magic_hits or []
    )


def high_signal_embedded_magic_hits(magic_hits, container_magic=None):
    high_signal = []
    low_signal_container_magic = {"PNG", "JPEG"}
    archive_or_document_magic = {"ELF", "ZIP", "7z", "RAR", "GZIP", "CAB", "OLE/CFB", "PDF"}

    for hit in magic_hits or []:
        magic = hit.get("magic")

        if magic == "PE/MZ":
            if hit.get("pe_validation", {}).get("valid"):
                high_signal.append(hit)
            continue

        if container_magic in low_signal_container_magic:
            continue

        if magic in archive_or_document_magic:
            high_signal.append(hit)

    return high_signal


def module_run(name, func, default, warnings):
    try:
        return func()
    except Exception as e:
        warnings.append(f"{name} failed: {type(e).__name__}: {e}")
        return default


def dedupe_keep_order(items):
    seen = set()
    result = []

    for item in items:
        marker = json.dumps(item, sort_keys=True) if isinstance(item, dict) else item

        if marker not in seen:
            result.append(item)
            seen.add(marker)

    return result


def add_finding(findings, finding_id, severity, confidence, title, evidence=None, recommendation=None):
    finding = {
        "id": finding_id,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "evidence": evidence or []
    }

    if recommendation:
        finding["recommendation"] = recommendation

    findings.append(finding)


def severity_rank(value):
    return {
        "high": 0,
        "medium": 1,
        "low": 2,
        "info": 3
    }.get(value, 4)


def confidence_rank(value):
    return {
        "high": 0,
        "medium": 1,
        "low": 2
    }.get(value, 3)


def pe_hashes(path, pe):
    data = read_file(path)

    result = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "imphash": None,
        "authentihash_sha256": None
    }

    try:
        result["imphash"] = pe.get_imphash()
    except Exception:
        pass

    try:
        result["authentihash_sha256"] = pe.get_authentihash(hashlib.sha256).hex()
    except Exception:
        pass

    return result


def characteristics(pe):
    flags = []

    values = {
        0x0001: "RELOCS_STRIPPED",
        0x0002: "EXECUTABLE_IMAGE",
        0x0004: "LINE_NUMS_STRIPPED",
        0x0008: "LOCAL_SYMS_STRIPPED",
        0x0020: "LARGE_ADDRESS_AWARE",
        0x0100: "32BIT_MACHINE",
        0x0200: "DEBUG_STRIPPED",
        0x0400: "REMOVABLE_RUN_FROM_SWAP",
        0x0800: "NET_RUN_FROM_SWAP",
        0x1000: "SYSTEM",
        0x2000: "DLL",
        0x4000: "UP_SYSTEM_ONLY"
    }

    chars = getattr(pe.FILE_HEADER, "Characteristics", 0)

    for bit, name in values.items():
        if chars & bit:
            flags.append(name)

    return flags


def dll_characteristics(pe):
    flags = []

    values = {
        0x0020: "HIGH_ENTROPY_VA",
        0x0040: "DYNAMIC_BASE/ASLR",
        0x0080: "FORCE_INTEGRITY",
        0x0100: "NX_COMPAT/DEP",
        0x0200: "NO_ISOLATION",
        0x0400: "NO_SEH",
        0x0800: "NO_BIND",
        0x1000: "APPCONTAINER",
        0x2000: "WDM_DRIVER",
        0x4000: "GUARD_CF",
        0x8000: "TERMINAL_SERVER_AWARE"
    }

    chars = getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)

    for bit, name in values.items():
        if chars & bit:
            flags.append(name)

    return flags


def dos_header(pe):
    return {
        "e_magic": hex(getattr(pe.DOS_HEADER, "e_magic", 0)),
        "e_lfanew": hex(getattr(pe.DOS_HEADER, "e_lfanew", 0))
    }


def file_header(pe):
    raw_ts = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)

    return {
        "machine": machine_type(getattr(pe.FILE_HEADER, "Machine", 0)),
        "machine_raw": hex(getattr(pe.FILE_HEADER, "Machine", 0)),
        "number_of_sections": getattr(pe.FILE_HEADER, "NumberOfSections", None),
        "timestamp_utc": timestamp_to_utc(raw_ts),
        "timestamp_raw": raw_ts,
        "timestamp_notes": timestamp_notes(raw_ts),
        "pointer_to_symbol_table": hex(getattr(pe.FILE_HEADER, "PointerToSymbolTable", 0)),
        "number_of_symbols": getattr(pe.FILE_HEADER, "NumberOfSymbols", None),
        "size_of_optional_header": getattr(pe.FILE_HEADER, "SizeOfOptionalHeader", None),
        "characteristics": characteristics(pe)
    }


def optional_header(pe):
    oh = pe.OPTIONAL_HEADER

    return {
        "magic": hex(getattr(oh, "Magic", 0)),
        "linker_version": f"{getattr(oh, 'MajorLinkerVersion', 0)}.{getattr(oh, 'MinorLinkerVersion', 0)}",
        "size_of_code": getattr(oh, "SizeOfCode", None),
        "size_of_initialized_data": getattr(oh, "SizeOfInitializedData", None),
        "size_of_uninitialized_data": getattr(oh, "SizeOfUninitializedData", None),
        "address_of_entry_point": hex(getattr(oh, "AddressOfEntryPoint", 0)),
        "image_base": hex(getattr(oh, "ImageBase", 0)),
        "section_alignment": getattr(oh, "SectionAlignment", None),
        "file_alignment": getattr(oh, "FileAlignment", None),
        "os_version": f"{getattr(oh, 'MajorOperatingSystemVersion', 0)}.{getattr(oh, 'MinorOperatingSystemVersion', 0)}",
        "image_version": f"{getattr(oh, 'MajorImageVersion', 0)}.{getattr(oh, 'MinorImageVersion', 0)}",
        "subsystem_version": f"{getattr(oh, 'MajorSubsystemVersion', 0)}.{getattr(oh, 'MinorSubsystemVersion', 0)}",
        "win32_version_value": getattr(oh, "Win32VersionValue", None),
        "size_of_image": getattr(oh, "SizeOfImage", None),
        "size_of_headers": getattr(oh, "SizeOfHeaders", None),
        "checksum": hex(getattr(oh, "CheckSum", 0)),
        "subsystem": subsystem_type(getattr(oh, "Subsystem", 0)),
        "dll_characteristics": dll_characteristics(pe),
        "stack_reserve": getattr(oh, "SizeOfStackReserve", None),
        "stack_commit": getattr(oh, "SizeOfStackCommit", None),
        "heap_reserve": getattr(oh, "SizeOfHeapReserve", None),
        "heap_commit": getattr(oh, "SizeOfHeapCommit", None),
        "loader_flags": getattr(oh, "LoaderFlags", None),
        "number_of_rva_and_sizes": getattr(oh, "NumberOfRvaAndSizes", None)
    }


def version_info(pe):
    result = {}

    if not hasattr(pe, "FileInfo"):
        return result

    for file_info in pe.FileInfo:
        if not isinstance(file_info, list):
            file_info = [file_info]

        for entry in file_info:
            if getattr(entry, "Key", None) == b"StringFileInfo":
                for string_table in entry.StringTable:
                    for key, value in string_table.entries.items():
                        result[safe_decode(key)] = safe_decode(value)

            elif getattr(entry, "Key", None) == b"VarFileInfo":
                for var in entry.Var:
                    result["Translation"] = str(var.entry)

    return result


def debug_info(pe):
    results = []

    if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        return results

    for dbg in pe.DIRECTORY_ENTRY_DEBUG:
        item = {
            "type": getattr(dbg.struct, "Type", None),
            "timestamp_utc": timestamp_to_utc(getattr(dbg.struct, "TimeDateStamp", 0)),
            "size_of_data": getattr(dbg.struct, "SizeOfData", None),
            "address_of_raw_data": hex(getattr(dbg.struct, "AddressOfRawData", 0)),
            "pointer_to_raw_data": hex(getattr(dbg.struct, "PointerToRawData", 0))
        }

        try:
            data = pe.get_data(dbg.struct.AddressOfRawData, dbg.struct.SizeOfData)

            if b"RSDS" in data:
                pdb = data.split(b"\x00")[0]
                item["pdb_path"] = safe_decode(pdb[24:])

            elif b"NB10" in data:
                pdb = data.split(b"\x00")[0]
                item["pdb_path"] = safe_decode(pdb[16:])

        except Exception:
            item["note"] = "Could not parse debug data"

        results.append(item)

    return results


def rich_header(pe):
    if not hasattr(pe, "RICH_HEADER") or not pe.RICH_HEADER:
        return None

    result = {
        "present": True
    }

    values = getattr(pe.RICH_HEADER, "values", None)

    if values:
        result["raw_values_count"] = len(values)

    try:
        result["clear_data_md5"] = hashlib.md5(pe.RICH_HEADER.clear_data).hexdigest()
    except Exception:
        pass

    try:
        rich_hash = pe.get_rich_header_hash()

        if isinstance(rich_hash, bytes):
            rich_hash = rich_hash.hex()

        result["rich_hash"] = rich_hash
    except Exception:
        pass

    return result


def is_weird_section_name(name):
    stripped = name.strip("\x00")

    if not stripped:
        return True

    if stripped in COMMON_SECTION_NAMES:
        return False

    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._$-")

    if any(ch not in allowed for ch in stripped):
        return True

    if len(stripped) >= 5 and not any(ch in ".$_" for ch in stripped) and stripped.lower() not in SUSPICIOUS_SECTION_NAMES:
        digits = sum(1 for ch in stripped if ch.isdigit())
        letters = sum(1 for ch in stripped if ch.isalpha())

        if digits >= 2 and letters >= 2:
            return True

    return False


def section_flags(section, section_entropy, file_size):
    flags = []
    chars = getattr(section, "Characteristics", 0)
    name = clean_section_name(section.Name)
    name_lower = name.lower()

    if chars & 0x20000000:
        flags.append("EXECUTE")
    if chars & 0x40000000:
        flags.append("READ")
    if chars & 0x80000000:
        flags.append("WRITE")
    if section_entropy >= 7.2:
        flags.append("HIGH_ENTROPY")
    if name_lower in SUSPICIOUS_SECTION_NAMES:
        flags.append("SUSPICIOUS_NAME")
    if not name:
        flags.append("EMPTY_NAME")
    elif is_weird_section_name(name):
        flags.append("UNUSUAL_NAME")
    if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
        flags.append("VIRTUAL_ONLY")
    if section.SizeOfRawData > 0 and section.Misc_VirtualSize > section.SizeOfRawData * 3:
        flags.append("LARGE_VIRTUAL_SIZE")
    if chars & 0x20000000 and chars & 0x80000000:
        flags.append("EXECUTE_WRITE")
    if chars & 0x20000000 and section.SizeOfRawData == 0:
        flags.append("EXECUTE_NO_RAW")
    if name_lower == ".text" and chars & 0x80000000:
        flags.append("TEXT_WRITABLE")
    if name_lower == ".rsrc" and chars & 0x20000000:
        flags.append("RESOURCE_EXECUTABLE")
    if name_lower == ".reloc" and chars & 0x20000000:
        flags.append("RELOC_EXECUTABLE")
    if section.PointerToRawData and section.SizeOfRawData and section.PointerToRawData + section.SizeOfRawData > file_size:
        flags.append("RAW_OUTSIDE_FILE")

    return flags


def section_ranges(pe):
    ranges = []

    for section in pe.sections:
        raw_start = section.PointerToRawData
        raw_end = raw_start + section.SizeOfRawData
        va_start = section.VirtualAddress
        va_end = va_start + max(section.Misc_VirtualSize, section.SizeOfRawData)

        ranges.append({
            "name": clean_section_name(section.Name),
            "raw_start": raw_start,
            "raw_end": raw_end,
            "va_start": va_start,
            "va_end": va_end
        })

    return ranges


def section_layout_anomalies(pe, file_size):
    anomalies = []
    ranges = section_ranges(pe)

    raw_ranges = [r for r in ranges if r["raw_end"] > r["raw_start"]]
    va_ranges = [r for r in ranges if r["va_end"] > r["va_start"]]

    for i, a in enumerate(raw_ranges):
        if a["raw_end"] > file_size:
            anomalies.append({
                "type": "raw_range_outside_file",
                "section": a["name"],
                "range": f"0x{a['raw_start']:x}-0x{a['raw_end']:x}"
            })

        for b in raw_ranges[i + 1:]:
            if max(a["raw_start"], b["raw_start"]) < min(a["raw_end"], b["raw_end"]):
                anomalies.append({
                    "type": "raw_range_overlap",
                    "sections": [a["name"], b["name"]],
                    "range_a": f"0x{a['raw_start']:x}-0x{a['raw_end']:x}",
                    "range_b": f"0x{b['raw_start']:x}-0x{b['raw_end']:x}"
                })

    for i, a in enumerate(va_ranges):
        for b in va_ranges[i + 1:]:
            if max(a["va_start"], b["va_start"]) < min(a["va_end"], b["va_end"]):
                anomalies.append({
                    "type": "virtual_range_overlap",
                    "sections": [a["name"], b["name"]],
                    "range_a": f"0x{a['va_start']:x}-0x{a['va_end']:x}",
                    "range_b": f"0x{b['va_start']:x}-0x{b['va_end']:x}"
                })

    return anomalies[:30]


def section_summary(pe, file_size):
    results = []

    for section in pe.sections:
        name = clean_section_name(section.Name)
        raw = section.get_data()
        ent = entropy(raw)

        results.append({
            "name": name,
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": section.Misc_VirtualSize,
            "raw_pointer": hex(section.PointerToRawData),
            "raw_size": section.SizeOfRawData,
            "raw_end": hex(section.PointerToRawData + section.SizeOfRawData),
            "entropy": round(ent, 2),
            "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            "characteristics": hex(section.Characteristics),
            "flags": section_flags(section, ent, file_size)
        })

    return results


def entry_point_info(pe):
    ep = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)

    result = {
        "entry_point_rva": hex(ep),
        "entry_point_file_offset": None,
        "section": None,
        "section_entropy": None,
        "section_flags": [],
        "is_in_section": False,
        "is_last_section": False
    }

    try:
        result["entry_point_file_offset"] = hex(pe.get_offset_from_rva(ep))
    except Exception:
        pass

    for index, section in enumerate(pe.sections):
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)

        if start <= ep < end:
            raw = section.get_data()
            ent = entropy(raw)

            result["section"] = clean_section_name(section.Name)
            result["section_entropy"] = round(ent, 2)
            result["section_flags"] = section_flags(section, ent, len(pe.__data__))
            result["is_in_section"] = True
            result["is_last_section"] = index == len(pe.sections) - 1
            break

    return result


def data_directories(pe):
    results = []

    for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if directory.VirtualAddress or directory.Size:
            results.append({
                "name": directory.name,
                "rva": hex(directory.VirtualAddress),
                "size": directory.Size
            })

    return results


def api_aliases(name):
    aliases = {name}

    if not name.endswith(("A", "W")):
        aliases.add(name + "A")
        aliases.add(name + "W")

    return aliases


def api_group_present(import_names, group):
    for item in group:
        for alias in api_aliases(item):
            if alias in import_names:
                return True

    return False


def detect_api_combinations(import_names):
    findings = []

    for rule in API_COMBINATION_RULES:
        if all(api_group_present(import_names, group) for group in rule["required"]):
            evidence = []

            for group in rule["required"]:
                matched = []

                for item in group:
                    for alias in api_aliases(item):
                        if alias in import_names:
                            matched.append(alias)

                evidence.append("/".join(sorted(set(matched))))

            findings.append({
                "id": rule["id"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "title": rule["title"],
                "evidence": evidence,
                "recommendation": rule["recommendation"]
            })

    return findings


def import_summary(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return {
            "import_table_present": False,
            "dll_count": 0,
            "import_count": 0,
            "ordinal_only_import_count": 0,
            "dlls": [],
            "interesting_imports": [],
            "capability_imports": {},
            "import_names": [],
            "api_combination_findings": []
        }

    dlls = []
    interesting = []
    import_names = set()
    import_count = 0
    ordinal_only = 0
    capability_imports = {category: [] for category in API_CATEGORIES}

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = safe_decode(entry.dll)
        dlls.append(dll)

        for imp in entry.imports:
            import_count += 1

            if not imp.name:
                ordinal_only += 1
                continue

            name = safe_decode(imp.name)
            full = f"{dll}!{name}"
            import_names.add(name)

            for category, api_names in API_CATEGORIES.items():
                if name in api_names:
                    capability_imports[category].append(full)
                    interesting.append(full)

    capability_imports = {
        category: sorted(set(values))[:30]
        for category, values in capability_imports.items()
        if values
    }

    return {
        "import_table_present": True,
        "dll_count": len(dlls),
        "import_count": import_count,
        "ordinal_only_import_count": ordinal_only,
        "dlls": sorted(set(dlls)),
        "interesting_imports": sorted(set(interesting))[:100],
        "capability_imports": capability_imports,
        "import_names": sorted(import_names),
        "api_combination_findings": detect_api_combinations(import_names)
    }


def delay_import_summary(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        return None

    dlls = []
    imports = []

    for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        dll = safe_decode(entry.dll)
        dlls.append(dll)

        for imp in entry.imports:
            if imp.name:
                imports.append(f"{dll}!{safe_decode(imp.name)}")

    return {
        "dll_count": len(dlls),
        "dlls": sorted(set(dlls)),
        "sample_imports": sorted(set(imports))[:40]
    }


def export_summary(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return None

    names = []
    ordinal_only = 0

    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if symbol.name:
            names.append(safe_decode(symbol.name))
        else:
            ordinal_only += 1

    return {
        "dll_name": safe_decode(pe.DIRECTORY_ENTRY_EXPORT.name),
        "export_count": len(pe.DIRECTORY_ENTRY_EXPORT.symbols),
        "named_export_count": len(names),
        "ordinal_only_export_count": ordinal_only,
        "sample_exports": names[:50]
    }


def resource_entry_label(entry, level):
    raw_id = getattr(entry.struct, "Id", None)
    raw_id_text = str(raw_id) if raw_id is not None else None

    if entry.name:
        label = str(entry.name)
        raw_label = label
        is_named = True
    else:
        if level == 0:
            label = pefile.RESOURCE_TYPE.get(raw_id, raw_id_text or "unknown")
        else:
            label = raw_id_text or "unknown"

        raw_label = raw_id_text or label
        is_named = False

    return {
        "label": label,
        "raw_label": raw_label,
        "id": raw_id,
        "name": str(entry.name) if entry.name else None,
        "is_named": is_named
    }


def compact_magic_hits(magic_hits):
    compact = []

    for hit in magic_hits or []:
        item = {
            "offset": hit.get("offset"),
            "magic": hit.get("magic"),
            "confidence": hit.get("confidence")
        }

        if hit.get("magic") == "PE/MZ":
            validation = hit.get("pe_validation", {})
            item["valid_pe"] = validation.get("valid")

            if validation.get("pe_header_offset"):
                item["pe_header_offset"] = validation.get("pe_header_offset")

            if hit.get("note"):
                item["note"] = hit.get("note")

        compact.append(item)

    return compact


def resource_priority(item):
    rtype = item.get("resource_type") or item.get("type")
    magic = item.get("magic_hint")
    magic_hits = item.get("embedded_magic_hits", [])
    size = item.get("size", 0)
    ent = item.get("entropy", 0.0)
    reasons = []
    low_signal_magic = {"PNG", "JPEG"}
    high_magic = {"PE/MZ", "ELF", "ZIP", "7z", "RAR", "GZIP", "CAB", "OLE/CFB"}
    medium_magic = {"PDF"}

    if magic == "PE/MZ":
        if item.get("top_level_pe_validation", {}).get("valid"):
            reasons.append("resource starts with a valid PE file")
            return "high", reasons

        reasons.append("resource starts with MZ but PE header validation failed")
        return "medium", reasons

    if magic in high_magic:
        reasons.append(f"resource starts with {magic} data")
        return "high", reasons

    if magic in medium_magic:
        reasons.append(f"resource starts with {magic} data")
        return "medium", reasons

    high_signal_hits = high_signal_embedded_magic_hits(magic_hits, container_magic=magic)

    if high_signal_hits:
        if any(hit.get("magic") == "PE/MZ" for hit in high_signal_hits):
            reasons.append("resource contains a validated embedded PE")
            return "high", reasons

        reasons.append(f"resource contains embedded {high_signal_hits[0].get('magic')} magic")
        return "high", reasons

    if magic in low_signal_magic:
        reasons.append(f"{magic} image data is usually compressed/high entropy")

        if size >= 1000000 and ent >= 7.5:
            reasons.append("image resource is unusually large and high entropy")
            return "medium", reasons

        return "low", reasons

    if rtype in LOW_SIGNAL_RESOURCE_TYPES:
        reasons.append(f"{rtype} is usually a low-signal resource type")

        if size >= 1000000 and ent >= 7.5:
            reasons.append("low-signal resource type is unusually large and high entropy")
            return "medium", reasons

        return "low", reasons

    if size >= 100000 and ent >= 7.2:
        reasons.append("large high-entropy resource")
        return "high", reasons

    if size >= 100000:
        reasons.append("large resource")
        return "medium", reasons

    if ent >= 7.5:
        reasons.append("high-entropy resource")
        return "medium", reasons

    if magic:
        reasons.append(f"resource starts with {magic} data")
        return "medium", reasons

    return "low", reasons


def walk_resources(pe, entries, path=None, raw_path=None, descriptors=None, level=0):
    if path is None:
        path = []

    if raw_path is None:
        raw_path = []

    if descriptors is None:
        descriptors = []

    items = []

    for entry in entries:
        descriptor = resource_entry_label(entry, level)
        new_path = path + [descriptor["label"]]
        new_raw_path = raw_path + [descriptor["raw_label"]]
        new_descriptors = descriptors + [descriptor]

        if hasattr(entry, "directory"):
            items.extend(walk_resources(pe, entry.directory.entries, new_path, new_raw_path, new_descriptors, level + 1))
        elif hasattr(entry, "data"):
            rva = entry.data.struct.OffsetToData
            size = entry.data.struct.Size
            codepage = getattr(entry.data.struct, "CodePage", None)
            data = pe.get_data(rva, size)
            file_offset = None

            try:
                file_offset = pe.get_offset_from_rva(rva)
            except Exception:
                pass

            top_level_magic = magic_hint(data)
            top_level_pe_validation = None

            if top_level_magic == "PE/MZ":
                top_level_pe_validation = validate_embedded_pe(data, 0)

            resource_type = new_path[0] if len(new_path) > 0 else None
            resource_name = new_path[1] if len(new_path) > 1 else None
            resource_language = new_path[2] if len(new_path) > 2 else None
            resource_type_raw = new_raw_path[0] if len(new_raw_path) > 0 else None
            resource_name_raw = new_raw_path[1] if len(new_raw_path) > 1 else None
            resource_language_raw = new_raw_path[2] if len(new_raw_path) > 2 else None
            embedded_magic_hits = find_magic_hits(data[:MAX_MAGIC_SCAN_BYTES], limit=10)

            item = {
                "resource_path": "/".join(new_path),
                "resource_raw_path": "/".join(new_raw_path),
                "resource_type": resource_type,
                "resource_name": resource_name,
                "resource_language": resource_language,
                "resource_type_raw": resource_type_raw,
                "resource_name_raw": resource_name_raw,
                "resource_language_raw": resource_language_raw,
                "type": resource_type,
                "name": resource_name,
                "language": resource_language,
                "path_depth": len(new_path),
                "codepage": codepage,
                "rva": hex(rva),
                "file_offset": hex(file_offset) if file_offset is not None else None,
                "file_offset_int": file_offset,
                "size": size,
                "entropy": round(entropy(data), 2),
                "sha256": hashlib.sha256(data).hexdigest() if data else None,
                "magic_hint": top_level_magic,
                "embedded_magic_hits": embedded_magic_hits,
                "embedded_magic_hits_compact": compact_magic_hits(embedded_magic_hits),
                "high_signal_embedded_magic_hits": high_signal_embedded_magic_hits(embedded_magic_hits, container_magic=top_level_magic),
                "range": {
                    "start": file_offset,
                    "end": file_offset + size if file_offset is not None else None
                }
            }

            if top_level_pe_validation is not None:
                item["top_level_pe_validation"] = top_level_pe_validation

            priority, reasons = resource_priority(item)
            item["priority"] = priority
            item["priority_reasons"] = reasons
            items.append(item)

    return items


def resource_summary(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None

    items = walk_resources(pe, pe.DIRECTORY_ENTRY_RESOURCE.entries)
    by_type = {}

    for item in items:
        rtype = item.get("resource_type") or "unknown"

        if rtype not in by_type:
            by_type[rtype] = {
                "count": 0,
                "max_size": 0,
                "max_entropy": 0.0,
                "highest_priority": "low",
                "interesting": []
            }

        by_type[rtype]["count"] += 1
        by_type[rtype]["max_size"] = max(by_type[rtype]["max_size"], item["size"])
        by_type[rtype]["max_entropy"] = max(by_type[rtype]["max_entropy"], item["entropy"])

        if severity_rank(item["priority"]) < severity_rank(by_type[rtype]["highest_priority"]):
            by_type[rtype]["highest_priority"] = item["priority"]

        if item["priority"] in {"high", "medium"}:
            by_type[rtype]["interesting"].append(item)

    for rtype in by_type:
        by_type[rtype]["max_entropy"] = round(by_type[rtype]["max_entropy"], 2)
        by_type[rtype]["interesting"] = by_type[rtype]["interesting"][:10]

    interesting_resources = [
        item for item in items
        if item["priority"] in {"high", "medium"}
    ][:30]

    ranges = []

    for item in items:
        start = item.get("range", {}).get("start")
        end = item.get("range", {}).get("end")

        if start is not None and end is not None:
            ranges.append({
                "resource_path": item.get("resource_path"),
                "resource_raw_path": item.get("resource_raw_path"),
                "resource_type": item.get("resource_type"),
                "resource_name": item.get("resource_name"),
                "resource_language": item.get("resource_language"),
                "type": item.get("resource_type"),
                "name": item.get("resource_name"),
                "language": item.get("resource_language"),
                "start": start,
                "end": end
            })

    return {
        "by_type": by_type,
        "items": items,
        "resource_count": len(items),
        "interesting_resources": interesting_resources,
        "ranges": ranges
    }


def tls_summary(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        return None

    tls = pe.DIRECTORY_ENTRY_TLS.struct
    image_base = getattr(pe.OPTIONAL_HEADER, "ImageBase", 0)
    magic = getattr(pe.OPTIONAL_HEADER, "Magic", 0)
    pointer_size = 8 if magic == 0x20b else 4
    callbacks = []

    try:
        callbacks_va = tls.AddressOfCallBacks
        callbacks_rva = callbacks_va - image_base

        for index in range(32):
            raw = pe.get_data(callbacks_rva + index * pointer_size, pointer_size)

            if len(raw) != pointer_size:
                break

            value = int.from_bytes(raw, "little")

            if value == 0:
                break

            callback_rva = value - image_base
            section_name = None

            for section in pe.sections:
                start = section.VirtualAddress
                end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)

                if start <= callback_rva < end:
                    section_name = clean_section_name(section.Name)
                    break

            callbacks.append({
                "va": hex(value),
                "rva": hex(callback_rva),
                "section": section_name
            })

    except Exception:
        pass

    return {
        "start_address_of_raw_data": hex(tls.StartAddressOfRawData),
        "end_address_of_raw_data": hex(tls.EndAddressOfRawData),
        "address_of_index": hex(tls.AddressOfIndex),
        "address_of_callbacks": hex(tls.AddressOfCallBacks),
        "callbacks": callbacks,
        "callback_count": len(callbacks),
        "size_of_zero_fill": tls.SizeOfZeroFill,
        "characteristics": hex(tls.Characteristics)
    }


def certificate_summary(pe):
    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]

    if security_dir.VirtualAddress == 0 or security_dir.Size == 0:
        return {
            "present": False
        }

    return {
        "present": True,
        "file_offset": hex(security_dir.VirtualAddress),
        "file_offset_int": security_dir.VirtualAddress,
        "size": security_dir.Size,
        "range": {
            "start": security_dir.VirtualAddress,
            "end": security_dir.VirtualAddress + security_dir.Size
        },
        "note": "Certificate table is present, but signature validity is not verified by this script"
    }


def overlay_summary(path, pe, certificate):
    offset = pe.get_overlay_data_start_offset()

    if offset is None:
        return None

    file_size = os.path.getsize(path)
    data = pe.__data__[offset:]
    overlay_end = file_size
    classification = "non_certificate_overlay"
    cert_range = certificate.get("range") if certificate else None

    if cert_range:
        cert_start = cert_range["start"]
        cert_end = cert_range["end"]

        if offset >= cert_start and overlay_end <= cert_end:
            classification = "certificate_table_only"
        elif offset == cert_start and overlay_end > cert_end:
            classification = "certificate_table_plus_extra_data"
        elif max(offset, cert_start) < min(overlay_end, cert_end):
            classification = "overlaps_certificate_table"

    return {
        "offset": hex(offset),
        "offset_int": offset,
        "size": file_size - offset,
        "entropy": round(entropy(data), 2),
        "sha256": hashlib.sha256(data).hexdigest() if data else None,
        "magic_hint": magic_hint(data),
        "embedded_magic_hits": find_magic_hits(data[:MAX_MAGIC_SCAN_BYTES], limit=10),
        "classification": classification
    }


def dotnet_info(pe):
    try:
        clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        ]

        if clr_dir.VirtualAddress == 0 or clr_dir.Size == 0:
            return {
                "is_dotnet": False
            }

        return {
            "is_dotnet": True,
            "clr_header_rva": hex(clr_dir.VirtualAddress),
            "clr_header_size": clr_dir.Size
        }

    except Exception:
        return {
            "is_dotnet": False
        }


def extract_ascii_strings(data, min_len=5):
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    results = []

    for match in re.finditer(pattern, data):
        decoded = match.group(0).decode("utf-8", errors="ignore").strip()

        if decoded:
            results.append({
                "value": decoded,
                "offset": match.start(),
                "encoding": "ascii"
            })

    return results


def extract_utf16le_strings(data, min_len=5):
    pattern = rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}"
    results = []

    for match in re.finditer(pattern, data):
        decoded = match.group(0).decode("utf-16le", errors="ignore").strip()

        if decoded:
            results.append({
                "value": decoded,
                "offset": match.start(),
                "encoding": "utf16le"
            })

    return results


def filter_domain_candidate(domain):
    bad_suffixes = (
        ".dll", ".exe", ".pdb", ".sys", ".ocx", ".dat", ".bin",
        ".tmp", ".log", ".txt", ".json", ".xml", ".html", ".config",
        ".manifest", ".mui", ".local"
    )

    bad_contains = (
        "microsoft.com/fwlink",
        "schemas.microsoft.com",
        "w3.org",
        "example.com",
        "example.org",
        "example.net"
    )

    d = domain.strip(".,;:)[]{}").lower()

    if not d:
        return None

    if d.endswith(bad_suffixes):
        return None

    if any(x in d for x in bad_contains):
        return None

    if len(d) > 253:
        return None

    labels = d.split(".")

    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return None

    return domain.strip(".,;:)[]{}")


def hostname_from_url(value):
    try:
        parsed = urlparse(value)
    except Exception:
        return None

    hostname = parsed.hostname

    if not hostname:
        return None

    return hostname.lower().strip(".")


def noisy_network_reason(value, origin=None):
    candidate = value.strip(".,;:)[]{}").lower()

    if candidate.startswith(("http://", "https://")):
        host = hostname_from_url(candidate)
    else:
        host = candidate

    if not host:
        return None

    if origin == "certificate_table":
        return "certificate_table_origin"

    labels = host.split(".")

    if host in NOISY_NETWORK_EXACT:
        return "known_certificate_or_crl_domain"

    if labels and labels[0] in {"crl", "ocsp", "crt", "cacerts", "certs"}:
        return "certificate_revocation_or_issuer_host"

    if any(host == suffix or host.endswith("." + suffix) for suffix in NOISY_NETWORK_SUFFIXES):
        return "known_certificate_authority_domain"

    if "schemas.microsoft.com" in host or host in {"w3.org", "www.w3.org"}:
        return "schema_or_standards_domain"

    return None


def classify_ipv4(ip):
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return None

    if obj.is_loopback:
        return "loopback"

    if obj.is_private:
        return "private"

    if obj.is_multicast:
        return "multicast"

    if obj.is_reserved:
        return "reserved"

    if obj.is_unspecified:
        return "unspecified"

    return "public"


def network_context_score(value, source_string):
    lowered = source_string.lower()
    terms = [
        "http", "https", "url", "host", "user-agent", "connect", "socket", "dns",
        "server", "gate", "api", "post", "get", "authorization", "bearer"
    ]

    if any(term in lowered for term in terms):
        return "medium"

    if value.lower().startswith(("http://", "https://")):
        return "high"

    return "low"


def origin_for_offset(offset, section_ranges_value, resource_ranges, overlay, certificate):
    cert_range = certificate.get("range") if certificate else None

    if cert_range and cert_range["start"] <= offset < cert_range["end"]:
        return "certificate_table"

    for resource in resource_ranges:
        if resource["start"] <= offset < resource["end"]:
            label = resource.get("resource_path") or resource.get("resource_type") or resource.get("type") or "unknown"
            return f"resource:{label}"

    if overlay and overlay.get("offset_int") is not None and offset >= overlay["offset_int"]:
        return f"overlay:{overlay.get('classification')}"

    for section in section_ranges_value:
        if section["raw_start"] <= offset < section["raw_end"]:
            return f"section:{section['name']}"

    return "headers_or_unknown"


def add_string_match(results, name, value, source, start_index, section_ranges_value, resource_ranges, overlay, certificate):
    if source["encoding"] == "utf16le":
        absolute_offset = source["offset"] + start_index * 2
    else:
        absolute_offset = source["offset"] + start_index

    item = {
        "value": value,
        "preview": preview(value),
        "offset": hex(absolute_offset),
        "offset_int": absolute_offset,
        "encoding": source["encoding"],
        "origin": origin_for_offset(absolute_offset, section_ranges_value, resource_ranges, overlay, certificate)
    }

    if name == "ipv4":
        classification = classify_ipv4(value)

        if not classification:
            return

        item["ip_type"] = classification
        item["confidence"] = "high" if classification == "public" else "low"

    elif name == "domains":
        filtered = filter_domain_candidate(value)

        if not filtered:
            return

        item["value"] = filtered
        item["preview"] = preview(filtered)
        noise_reason = noisy_network_reason(filtered, item.get("origin"))

        if noise_reason:
            item["confidence"] = "noise"
            item["noise_reason"] = noise_reason
        else:
            item["confidence"] = network_context_score(filtered, source["value"])

    elif name == "urls":
        noise_reason = noisy_network_reason(value, item.get("origin"))

        if noise_reason:
            item["confidence"] = "noise"
            item["noise_reason"] = noise_reason
        else:
            item["confidence"] = "high"

    else:
        item["confidence"] = "medium"

    results.setdefault(name, []).append(item)


def unique_string_items(items, max_items):
    result = []
    seen = set()

    for item in sorted(items, key=lambda x: (x.get("value", ""), x.get("offset_int", 0))):
        marker = (item.get("value"), item.get("origin"), item.get("encoding"))

        if marker in seen:
            continue

        cleaned = dict(item)
        cleaned.pop("offset_int", None)
        result.append(cleaned)
        seen.add(marker)

        if len(result) >= max_items:
            break

    return result


def decode_base64_candidate(value):
    candidate = value.strip()
    padding = "=" * ((4 - len(candidate) % 4) % 4)

    try:
        return base64.b64decode(candidate + padding, validate=True)
    except Exception:
        return None


def decode_hex_candidate(value):
    candidate = value.strip()

    try:
        return bytes.fromhex(candidate)
    except Exception:
        return None


def scan_decoded_blob(decoded, blob_type):
    strings = [item["value"] for item in extract_ascii_strings(decoded, min_len=5)[:200]]
    joined = "\n".join(strings)
    urls = sorted(set(STRING_PATTERNS["urls"].findall(joined)))[:10]
    ipv4 = []
    domains = []

    for value in sorted(set(STRING_PATTERNS["ipv4"].findall(joined))):
        classification = classify_ipv4(value)

        if classification:
            ipv4.append({
                "value": value,
                "type": classification
            })

        if len(ipv4) >= 10:
            break

    for value in sorted(set(STRING_PATTERNS["domains"].findall(joined))):
        filtered = filter_domain_candidate(value)

        if filtered:
            domains.append(filtered)

        if len(domains) >= 10:
            break

    return {
        "type": blob_type,
        "decoded_size": len(decoded),
        "decoded_entropy": round(entropy(decoded), 2),
        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
        "magic_hint": magic_hint(decoded),
        "embedded_magic_hits": find_magic_hits(decoded[:MAX_MAGIC_SCAN_BYTES], limit=10),
        "urls": urls,
        "ipv4": ipv4,
        "domains": domains,
        "sample_strings": [preview(s, 100) for s in strings[:10]]
    }


def encoded_blob_candidates(string_entries, section_ranges_value, resource_ranges, overlay, certificate, max_candidates=20):
    candidates = []
    seen = set()

    for source in string_entries:
        value = source["value"]

        for match in STRING_PATTERNS["base64_like"].finditer(value):
            candidate = match.group(0)

            if candidate in seen:
                continue

            seen.add(candidate)
            decoded = decode_base64_candidate(candidate)

            if not decoded or len(decoded) < 16:
                continue

            absolute_offset = source["offset"] + (match.start() * 2 if source["encoding"] == "utf16le" else match.start())
            item = scan_decoded_blob(decoded[:5 * 1024 * 1024], "base64")
            item["source_preview"] = preview(candidate)
            item["source_offset"] = hex(absolute_offset)
            item["source_origin"] = origin_for_offset(absolute_offset, section_ranges_value, resource_ranges, overlay, certificate)
            candidates.append(item)

            if len(candidates) >= max_candidates:
                return candidates

        for match in STRING_PATTERNS["hex_like"].finditer(value):
            candidate = match.group(0)

            if candidate in seen:
                continue

            seen.add(candidate)
            decoded = decode_hex_candidate(candidate)

            if not decoded or len(decoded) < 16:
                continue

            absolute_offset = source["offset"] + (match.start() * 2 if source["encoding"] == "utf16le" else match.start())
            item = scan_decoded_blob(decoded[:5 * 1024 * 1024], "hex")
            item["source_preview"] = preview(candidate)
            item["source_offset"] = hex(absolute_offset)
            item["source_origin"] = origin_for_offset(absolute_offset, section_ranges_value, resource_ranges, overlay, certificate)
            candidates.append(item)

            if len(candidates) >= max_candidates:
                return candidates

    return candidates


def interesting_string_scan(path, pe, resources, overlay, certificate, max_items_per_category=30):
    data = read_file(path)
    ascii_strings = extract_ascii_strings(data)
    wide_strings = extract_utf16le_strings(data)
    string_entries = ascii_strings + wide_strings
    section_ranges_value = section_ranges(pe)
    resource_ranges = resources.get("ranges", []) if resources else []
    results = {}

    for name, pattern in STRING_PATTERNS.items():
        if name in {"base64_like", "hex_like"}:
            continue

        results[name] = []

        for source in string_entries:
            for match in pattern.finditer(source["value"]):
                add_string_match(results, name, match.group(0), source, match.start(), section_ranges_value, resource_ranges, overlay, certificate)

        results[name] = unique_string_items(results[name], max_items_per_category)

    keyword_hits = {}

    for category, keywords in KEYWORD_CATEGORIES.items():
        hits = []

        for source in string_entries:
            lowered = source["value"].lower()

            if keyword_category_match(category, source["value"], lowered, keywords):
                origin = origin_for_offset(source["offset"], section_ranges_value, resource_ranges, overlay, certificate)
                hits.append({
                    "value": source["value"],
                    "preview": preview(source["value"]),
                    "offset": hex(source["offset"]),
                    "encoding": source["encoding"],
                    "origin": origin
                })

        keyword_hits[category] = unique_string_items(hits, max_items_per_category)

    base64_total = 0
    hex_total = 0
    base64_longest = 0
    hex_longest = 0

    for source in string_entries:
        base64_matches = STRING_PATTERNS["base64_like"].findall(source["value"])
        hex_matches = STRING_PATTERNS["hex_like"].findall(source["value"])
        base64_total += len(base64_matches)
        hex_total += len(hex_matches)
        base64_longest = max([base64_longest] + [len(x) for x in base64_matches])
        hex_longest = max([hex_longest] + [len(x) for x in hex_matches])

    results["keyword_hits"] = keyword_hits
    results["encoded_blobs"] = encoded_blob_candidates(string_entries, section_ranges_value, resource_ranges, overlay, certificate)
    results["stats"] = {
        "ascii_string_count": len(ascii_strings),
        "utf16le_string_count": len(wide_strings),
        "unique_combined_string_count": len(set(item["value"] for item in string_entries)),
        "longest_string_length": max((len(item["value"]) for item in string_entries), default=0),
        "base64_like_total_count": base64_total,
        "hex_like_total_count": hex_total,
        "base64_like_longest_length": base64_longest,
        "hex_like_longest_length": hex_longest
    }

    return results


def collect_artifacts(summary):
    artifacts = []
    version = summary.get("version_info", {})

    for key in ["OriginalFilename", "InternalName", "FileDescription", "CompanyName", "ProductName", "ProductVersion", "FileVersion"]:
        if version.get(key):
            artifacts.append({
                "type": "version_info",
                "name": key,
                "value": version[key]
            })

    for item in summary.get("debug", []):
        if item.get("pdb_path"):
            artifacts.append({
                "type": "debug",
                "name": "PDB path",
                "value": item["pdb_path"]
            })

    for item in summary.get("strings", {}).get("pdb_paths", []):
        artifacts.append({
            "type": "string",
            "name": "PDB path candidate",
            "value": item.get("value"),
            "origin": item.get("origin"),
            "offset": item.get("offset")
        })

    ep = summary.get("entry_point", {})
    artifacts.append({
        "type": "entry_point",
        "name": "Entry point",
        "value": f"{ep.get('entry_point_rva')} in {ep.get('section')}"
    })

    if summary.get("overlay"):
        overlay = summary["overlay"]
        artifacts.append({
            "type": "overlay",
            "name": "Overlay",
            "value": f"{overlay.get('classification')}, size={overlay.get('size')}, entropy={overlay.get('entropy')}"
        })

    if summary.get("tls"):
        tls = summary["tls"]
        artifacts.append({
            "type": "tls",
            "name": "TLS callbacks",
            "value": str(tls.get("callback_count", 0))
        })

    if summary.get("dotnet", {}).get("is_dotnet"):
        artifacts.append({
            "type": "dotnet",
            "name": ".NET/CLR",
            "value": "present"
        })

    return artifacts


def network_indicator_counts(strings):
    urls = [item for item in strings.get("urls", []) if item.get("confidence") != "noise"]
    noisy_urls = [item for item in strings.get("urls", []) if item.get("confidence") == "noise"]
    public_ips = [item for item in strings.get("ipv4", []) if item.get("ip_type") == "public"]
    medium_high_domains = [item for item in strings.get("domains", []) if item.get("confidence") in {"medium", "high"}]
    low_domains = [item for item in strings.get("domains", []) if item.get("confidence") == "low"]
    noisy_domains = [item for item in strings.get("domains", []) if item.get("confidence") == "noise"]

    return {
        "urls": len(urls),
        "public_ipv4": len(public_ips),
        "medium_high_domains": len(medium_high_domains),
        "low_confidence_domains": len(low_domains),
        "noisy_urls": len(noisy_urls),
        "noisy_domains": len(noisy_domains)
    }


def generate_findings(summary):
    findings = []
    sections = summary.get("sections", [])
    imports = summary.get("imports", {})
    ep = summary.get("entry_point", {})
    strings = summary.get("strings", {})
    resources = summary.get("resources")
    overlay = summary.get("overlay")
    optional = summary.get("optional_header", {})

    high_entropy_sections = [s["name"] for s in sections if "HIGH_ENTROPY" in s.get("flags", [])]
    execute_write_sections = [s["name"] for s in sections if "EXECUTE_WRITE" in s.get("flags", [])]
    suspicious_name_sections = [s["name"] for s in sections if "SUSPICIOUS_NAME" in s.get("flags", [])]
    structural_flags = []

    for section in sections:
        relevant = [
            flag for flag in section.get("flags", [])
            if flag in {"RAW_OUTSIDE_FILE", "EXECUTE_NO_RAW", "TEXT_WRITABLE", "RESOURCE_EXECUTABLE", "RELOC_EXECUTABLE", "EMPTY_NAME", "UNUSUAL_NAME"}
        ]

        if relevant:
            structural_flags.append(f"{section['name']}: {', '.join(relevant)}")

    if high_entropy_sections:
        add_finding(
            findings,
            "section_high_entropy",
            "medium",
            "medium",
            "High-entropy section data",
            [", ".join(high_entropy_sections)],
            "Check for packing, encryption, compressed payloads, or embedded configuration."
        )

    if execute_write_sections:
        add_finding(
            findings,
            "section_execute_write",
            "medium",
            "medium",
            "Executable and writable section(s)",
            [", ".join(execute_write_sections)],
            "Inspect these sections first if execution reaches them."
        )

    if suspicious_name_sections:
        add_finding(
            findings,
            "section_suspicious_name",
            "medium",
            "medium",
            "Suspicious section name(s)",
            [", ".join(suspicious_name_sections)],
            "Correlate section name with entropy, entry point, and import table size."
        )

    if structural_flags:
        add_finding(
            findings,
            "section_structural_anomaly",
            "medium",
            "medium",
            "Section layout or permission anomaly",
            structural_flags[:10],
            "Inspect section headers and verify whether the PE is malformed, packed, or intentionally unusual."
        )

    if summary.get("section_layout_anomalies"):
        evidence = [str(item) for item in summary["section_layout_anomalies"][:5]]
        add_finding(
            findings,
            "section_range_anomaly",
            "medium",
            "medium",
            "Overlapping or invalid section ranges",
            evidence,
            "Use PEStudio or pefile output to verify whether the file uses malformed PE layout tricks."
        )

    if not ep.get("is_in_section"):
        add_finding(
            findings,
            "entry_point_outside_sections",
            "high",
            "medium",
            "Entry point is outside known sections",
            [f"EP={ep.get('entry_point_rva')}"],
            "Manually verify the entry point mapping before trusting automated disassembly."
        )

    if ep.get("section_entropy") and ep["section_entropy"] >= 7.2:
        add_finding(
            findings,
            "entry_point_high_entropy",
            "high",
            "medium",
            "Entry point is in a high-entropy section",
            [f"{ep.get('section')} entropy={ep.get('section_entropy')}"],
            "Prioritize FLOSS, unpacking, or debugger-assisted dumping."
        )

    if "WRITE" in ep.get("section_flags", []):
        add_finding(
            findings,
            "entry_point_writable_section",
            "medium",
            "medium",
            "Entry point section is writable",
            [f"{ep.get('section')} flags={', '.join(ep.get('section_flags', []))}"],
            "Inspect for unpacking stubs or self-modifying code."
        )

    if ep.get("is_last_section") and len(sections) >= 3:
        add_finding(
            findings,
            "entry_point_last_section",
            "medium",
            "low",
            "Entry point is in the last section",
            [f"EP section={ep.get('section')}"],
            "Correlate with section entropy and imports before treating this as suspicious."
        )

    if not imports.get("import_table_present"):
        add_finding(
            findings,
            "imports_absent",
            "medium",
            "medium",
            "No normal import table found",
            ["Import table missing or not parsed"],
            "Assume dynamic API resolution, packing, or malformed imports until checked."
        )

    if imports.get("import_table_present") and imports.get("dll_count", 0) <= 2 and imports.get("import_count", 0) <= 20:
        add_finding(
            findings,
            "imports_very_small",
            "medium",
            "medium",
            "Very small import table",
            [f"dll_count={imports.get('dll_count')}", f"import_count={imports.get('import_count')}"],
            "Look for dynamic API resolution and unpacked imports after execution."
        )

    if imports.get("ordinal_only_import_count", 0) > 0:
        add_finding(
            findings,
            "imports_ordinal_only",
            "low",
            "medium",
            "Ordinal-only imports found",
            [f"ordinal_only_import_count={imports.get('ordinal_only_import_count')}"],
            "Resolve ordinal imports manually if they affect behavior."
        )

    for item in imports.get("api_combination_findings", []):
        findings.append(item)

    if summary.get("delay_imports"):
        add_finding(
            findings,
            "imports_delay_imports",
            "low",
            "medium",
            "Delay imports are present",
            summary["delay_imports"].get("dlls", []),
            "Check delay-loaded APIs if normal imports look incomplete."
        )

    if summary.get("tls"):
        tls = summary["tls"]
        evidence = [f"callback_count={tls.get('callback_count')}"]

        for callback in tls.get("callbacks", [])[:10]:
            evidence.append(f"{callback.get('va')} {callback.get('section')}")

        add_finding(
            findings,
            "tls_present",
            "medium",
            "medium",
            "TLS directory is present",
            evidence,
            "Check TLS callbacks because code may execute before the normal entry point."
        )

    if overlay and overlay.get("classification") != "certificate_table_only":
        severity = "medium"
        confidence = "medium"
        title = "Non-certificate overlay data is present"
        evidence = [
            f"classification={overlay.get('classification')}",
            f"size={overlay.get('size')}",
            f"entropy={overlay.get('entropy')}"
        ]

        if overlay.get("magic_hint"):
            evidence.append(f"magic={overlay.get('magic_hint')}")

        if overlay.get("embedded_magic_hits"):
            evidence.append(f"embedded_magic={overlay.get('embedded_magic_hits')[0]}")
            severity = "high"

        add_finding(
            findings,
            "overlay_non_certificate",
            severity,
            confidence,
            title,
            evidence,
            "Inspect or carve overlay data."
        )

    if resources and resources.get("interesting_resources"):
        high_resources = [item for item in resources["interesting_resources"] if item.get("priority") == "high"]
        severity = "high" if high_resources else "medium"
        evidence = []

        for item in resources["interesting_resources"][:10]:
            reason_text = "; ".join(item.get("priority_reasons", [])) or "-"
            evidence.append(
                f"path={item.get('resource_path')}, raw_path={item.get('resource_raw_path')}, "
                f"type={item.get('resource_type')}, name={item.get('resource_name')}, lang={item.get('resource_language')}, "
                f"size={item.get('size')}, entropy={item.get('entropy')}, magic={item.get('magic_hint')}, "
                f"priority={item.get('priority')}, reason={reason_text}"
            )

        add_finding(
            findings,
            "resources_interesting",
            severity,
            "medium",
            "Interesting resource data found",
            evidence,
            "Inspect high-entropy, large, or embedded-magic resources for payloads/configuration."
        )

    encoded_blobs = strings.get("encoded_blobs", [])
    encoded_evidence = []
    encoded_severity = "medium"

    for blob in encoded_blobs:
        if blob.get("magic_hint") or blob.get("embedded_magic_hits") or blob.get("urls") or blob.get("domains") or blob.get("ipv4"):
            encoded_evidence.append(
                f"{blob.get('type')} at {blob.get('source_offset')} origin={blob.get('source_origin')} magic={blob.get('magic_hint')} size={blob.get('decoded_size')}"
            )

            if blob.get("magic_hint") == "PE/MZ" or any(hit.get("magic") == "PE/MZ" for hit in blob.get("embedded_magic_hits", [])):
                encoded_severity = "high"

    if encoded_evidence:
        add_finding(
            findings,
            "encoded_blob_interesting",
            encoded_severity,
            "medium",
            "Encoded blob decodes to interesting content",
            encoded_evidence[:10],
            "Review decoded blob output and carve it if it contains embedded magic or indicators."
        )

    counts = network_indicator_counts(strings)

    if counts["urls"] or counts["public_ipv4"] or counts["medium_high_domains"]:
        evidence = [
            f"urls={counts['urls']}",
            f"public_ipv4={counts['public_ipv4']}",
            f"medium_high_domains={counts['medium_high_domains']}",
            f"low_confidence_domains={counts['low_confidence_domains']}",
            f"noisy_urls={counts['noisy_urls']}",
            f"noisy_domains={counts['noisy_domains']}"
        ]
        add_finding(
            findings,
            "strings_network_indicators",
            "medium",
            "medium" if counts["urls"] or counts["public_ipv4"] else "low",
            "Network string indicators found",
            evidence,
            "Review candidates manually before treating them as IOCs."
        )

    if strings.get("pdb_paths") or any(item.get("pdb_path") for item in summary.get("debug", [])):
        evidence = []

        for item in strings.get("pdb_paths", [])[:5]:
            evidence.append(f"{item.get('value')} at {item.get('offset')} {item.get('origin')}")

        for item in summary.get("debug", []):
            if item.get("pdb_path"):
                evidence.append(item["pdb_path"])

        add_finding(
            findings,
            "debug_pdb_path",
            "low",
            "high",
            "PDB path artifact found",
            evidence[:10],
            "Use the path for developer/machine/project-name clues."
        )

    for note in summary.get("file_header", {}).get("timestamp_notes", []):
        add_finding(
            findings,
            "timestamp_anomaly",
            "low",
            "medium",
            "Compile timestamp anomaly",
            [note],
            "Treat timestamp as weak evidence unless supported by other findings."
        )

    mitigation_flags = set(optional.get("dll_characteristics", []))
    missing_mitigations = []

    if "DYNAMIC_BASE/ASLR" not in mitigation_flags:
        missing_mitigations.append("ASLR/DYNAMIC_BASE absent")

    if "NX_COMPAT/DEP" not in mitigation_flags:
        missing_mitigations.append("DEP/NX_COMPAT absent")

    if missing_mitigations:
        add_finding(
            findings,
            "mitigations_missing_aslr_dep",
            "info",
            "medium",
            "Common mitigation flag(s) absent",
            missing_mitigations,
            "Treat this as weak context only; older legitimate PE files may also lack these flags."
        )

    if summary.get("dotnet", {}).get("is_dotnet"):
        add_finding(
            findings,
            "dotnet_present",
            "info",
            "high",
            ".NET/CLR header is present",
            [f"CLR header RVA={summary['dotnet'].get('clr_header_rva')}"] ,
            "Use .NET-specific tooling if deeper analysis is needed."
        )

    ordered = sorted(findings, key=lambda item: (severity_rank(item.get("severity")), confidence_rank(item.get("confidence")), item.get("id", "")))

    return dedupe_keep_order(ordered)


def triage_verdict(summary):
    findings = summary.get("findings", [])
    ids = {item.get("id") for item in findings}
    high_medium = [item for item in findings if item.get("severity") in {"high", "medium"}]

    verdict = {
        "likely_packed": False,
        "has_debug_artifacts": "debug_pdb_path" in ids,
        "has_network_indicators": "strings_network_indicators" in ids,
        "has_suspicious_section_layout": any(item in ids for item in {
            "section_execute_write", "section_suspicious_name", "entry_point_high_entropy",
            "entry_point_writable_section", "section_structural_anomaly", "section_range_anomaly",
            "entry_point_outside_sections"
        }),
        "has_interesting_resources": "resources_interesting" in ids,
        "summary": []
    }

    if any(item in ids for item in {"entry_point_high_entropy", "imports_absent", "imports_very_small", "section_high_entropy"}):
        verdict["likely_packed"] = True

    for item in high_medium[:8]:
        verdict["summary"].append(f"{item.get('severity').upper()}/{item.get('confidence')}: {item.get('title')}")

    if not verdict["summary"]:
        verdict["summary"].append("No strong structural anomalies identified by this script")

    return verdict


def what_to_inspect_first(summary):
    items = []

    for finding in summary.get("findings", []):
        if finding.get("severity") not in {"high", "medium"}:
            continue

        evidence = finding.get("evidence", [])
        text = finding.get("title", "Finding")

        if evidence:
            text += f" ({preview(evidence[0], 100)})"

        items.append(text)

        if len(items) >= 7:
            break

    if not items:
        items.append("No high-priority local triage finding was triggered")

    return items


def recommended_next_steps(summary):
    steps = []
    ids = {item.get("id") for item in summary.get("findings", [])}

    if "entry_point_high_entropy" in ids or "imports_absent" in ids or "imports_very_small" in ids:
        steps.append("Run FLOSS because packing or dynamic string/API resolution is plausible")
        steps.append("Consider unpacking or dumping if the sample executes safely in a controlled lab")

    if "encoded_blob_interesting" in ids:
        steps.append("Review decoded base64/hex blob output and carve decoded payloads if useful")

    if "resources_interesting" in ids:
        steps.append("Inspect high-entropy, large, or embedded-magic resources for payloads or config")

    if "overlay_non_certificate" in ids:
        steps.append("Inspect or carve overlay data because non-certificate overlay data is present")

    if "tls_present" in ids:
        steps.append("Check TLS callbacks because code may execute before the normal entry point")

    if any(item in ids for item in {"section_execute_write", "section_suspicious_name", "section_structural_anomaly", "entry_point_writable_section", "entry_point_outside_sections"}):
        steps.append("Inspect the entry-point section and anomalous sections in PEStudio/IDA/x64dbg")

    if any(item.startswith("api_") for item in ids):
        steps.append("Run capa to summarize code-level capabilities and confirm import-based hints")

    if "strings_network_indicators" in ids:
        steps.append("Review network candidates manually before treating them as IOCs")

    if "api_dpapi_credential_access" in ids or "api_process_dumping" in ids:
        steps.append("Check for credential, browser, token, wallet, or process-dump targeting strings")

    if "dotnet_present" in ids:
        steps.append("Use .NET-specific tooling because CLR metadata is present")

    if not steps:
        steps.append("Open in PEStudio/capa/FLOSS if deeper analysis is needed; no specific next step was triggered")

    return dedupe_keep_order(steps)


def summarize(path):
    pe = pefile.PE(path, fast_load=False)
    warnings = []
    file_size = os.path.getsize(path)

    certificate = module_run("certificate", lambda: certificate_summary(pe), {"present": False}, warnings)
    overlay = module_run("overlay", lambda: overlay_summary(path, pe, certificate), None, warnings)
    resources = module_run("resources", lambda: resource_summary(pe), None, warnings)

    summary = {
        "file": {
            "name": os.path.basename(path),
            "path": os.path.abspath(path),
            "size_bytes": file_size
        },
        "hashes": module_run("hashes", lambda: pe_hashes(path, pe), {}, warnings),
        "dos_header": module_run("dos_header", lambda: dos_header(pe), {}, warnings),
        "file_header": module_run("file_header", lambda: file_header(pe), {}, warnings),
        "optional_header": module_run("optional_header", lambda: optional_header(pe), {}, warnings),
        "version_info": module_run("version_info", lambda: version_info(pe), {}, warnings),
        "rich_header": module_run("rich_header", lambda: rich_header(pe), None, warnings),
        "debug": module_run("debug_info", lambda: debug_info(pe), [], warnings),
        "entry_point": module_run("entry_point", lambda: entry_point_info(pe), {}, warnings),
        "sections": module_run("sections", lambda: section_summary(pe, file_size), [], warnings),
        "section_layout_anomalies": module_run("section_layout_anomalies", lambda: section_layout_anomalies(pe, file_size), [], warnings),
        "data_directories": module_run("data_directories", lambda: data_directories(pe), [], warnings),
        "imports": module_run("imports", lambda: import_summary(pe), {}, warnings),
        "delay_imports": module_run("delay_imports", lambda: delay_import_summary(pe), None, warnings),
        "exports": module_run("exports", lambda: export_summary(pe), None, warnings),
        "resources": resources,
        "tls": module_run("tls", lambda: tls_summary(pe), None, warnings),
        "overlay": overlay,
        "certificate": certificate,
        "dotnet": module_run("dotnet", lambda: dotnet_info(pe), {"is_dotnet": False}, warnings),
        "parser_warnings": warnings
    }

    summary["strings"] = module_run("interesting_string_scan", lambda: interesting_string_scan(path, pe, resources, overlay, certificate), {}, warnings)
    summary["key_artifacts"] = collect_artifacts(summary)
    summary["findings"] = generate_findings(summary)
    summary["triage_verdict"] = triage_verdict(summary)
    summary["what_to_inspect_first"] = what_to_inspect_first(summary)
    summary["recommended_next_steps"] = recommended_next_steps(summary)

    pe.close()

    return summary


def format_chat_summary(summary):
    lines = []
    file_info = summary["file"]
    hashes = summary["hashes"]
    fh = summary["file_header"]
    oh = summary["optional_header"]
    ep = summary["entry_point"]

    lines.append(
        f"{file_info.get('name')} is a {fh.get('machine')} PE with subsystem "
        f"{oh.get('subsystem')}."
    )
    lines.append(f"SHA256: {hashes.get('sha256')}")
    lines.append(f"Compile timestamp UTC: {fh.get('timestamp_utc')}")
    lines.append(
        f"Entry point: {ep.get('entry_point_rva')} in section {ep.get('section')} "
        f"(entropy={ep.get('section_entropy')}, flags={', '.join(ep.get('section_flags', [])) or '-'})"
    )

    if summary.get("dotnet", {}).get("is_dotnet"):
        lines.append("Runtime: .NET/CLR header present")

    if summary.get("overlay"):
        overlay = summary["overlay"]
        lines.append(f"Overlay: {overlay.get('classification')}, size={overlay.get('size')}, entropy={overlay.get('entropy')}")

    counts = network_indicator_counts(summary.get("strings", {}))
    lines.append(
        "String network candidates: "
        f"urls={counts['urls']}, public_ipv4={counts['public_ipv4']}, "
        f"medium_high_domains={counts['medium_high_domains']}, low_confidence_domains={counts['low_confidence_domains']}, "
        f"noisy_urls={counts['noisy_urls']}, noisy_domains={counts['noisy_domains']}"
    )

    for item in summary["triage_verdict"]["summary"][:5]:
        lines.append(f"Verdict note: {item}")

    lines.append("")

    return lines


def format_finding(lines, finding):
    lines.append(f"- [{finding.get('severity').upper()} / {finding.get('confidence')}] {finding.get('title')} ({finding.get('id')})")

    for evidence in finding.get("evidence", [])[:8]:
        lines.append(f"    Evidence: {preview(evidence)}")

    if finding.get("recommendation"):
        lines.append(f"    Next: {finding.get('recommendation')}")


def format_string_items(lines, label, values):
    lines.append(f"{label}:")

    if values:
        for item in values:
            confidence = item.get("confidence")
            suffix_parts = [item.get("offset"), item.get("origin"), item.get("encoding")]

            if confidence:
                suffix_parts.append(f"confidence={confidence}")

            if item.get("ip_type"):
                suffix_parts.append(f"type={item.get('ip_type')}")

            if item.get("noise_reason"):
                suffix_parts.append(f"noise={item.get('noise_reason')}")

            suffix = ", ".join(str(x) for x in suffix_parts if x)
            lines.append(f"  {preview(item.get('value'))} [{suffix}]")
    else:
        lines.append("  None")


def format_text(summary):
    lines = []
    file_info = summary["file"]
    hashes = summary["hashes"]

    lines.append("PE TRIAGE SUMMARY")
    lines.append("=" * 80)
    lines.append("")
    lines.extend(format_chat_summary(summary))

    lines.append("WHAT TO INSPECT FIRST")
    lines.append("-" * 80)
    for index, item in enumerate(summary.get("what_to_inspect_first", []), 1):
        lines.append(f"{index}. {item}")
    lines.append("")

    lines.append("FILE IDENTITY")
    lines.append("-" * 80)
    lines.append(f"File: {file_info.get('name')}")
    lines.append(f"Path: {file_info.get('path')}")
    lines.append(f"Size: {file_info.get('size_bytes')} bytes")
    lines.append(f"MD5: {hashes.get('md5')}")
    lines.append(f"SHA1: {hashes.get('sha1')}")
    lines.append(f"SHA256: {hashes.get('sha256')}")
    lines.append(f"Imphash: {hashes.get('imphash')}")
    lines.append(f"Authentihash SHA256: {hashes.get('authentihash_sha256')}")
    lines.append("")

    lines.append("TRIAGE VERDICT")
    lines.append("-" * 80)
    for item in summary["triage_verdict"]["summary"]:
        lines.append(f"- {item}")
    lines.append("")

    lines.append("STRUCTURED FINDINGS")
    lines.append("-" * 80)
    if summary.get("findings"):
        for finding in summary["findings"]:
            format_finding(lines, finding)
    else:
        lines.append("No findings generated")
    lines.append("")

    lines.append("RECOMMENDED NEXT STEPS")
    lines.append("-" * 80)
    for step in summary["recommended_next_steps"]:
        lines.append(f"- {step}")
    lines.append("")

    lines.append("KEY ARTIFACTS")
    lines.append("-" * 80)
    if summary.get("key_artifacts"):
        for artifact in summary["key_artifacts"]:
            parts = [artifact.get("type"), artifact.get("name"), artifact.get("value")]

            if artifact.get("origin"):
                parts.append(artifact.get("origin"))

            if artifact.get("offset"):
                parts.append(artifact.get("offset"))

            lines.append(" | ".join(str(part) for part in parts if part is not None))
    else:
        lines.append("No key artifacts found")
    lines.append("")

    lines.append("INTERESTING STRING CANDIDATES")
    lines.append("-" * 80)
    strings = summary.get("strings", {})
    stats = strings.get("stats", {})
    lines.append(f"ASCII string count: {stats.get('ascii_string_count')}")
    lines.append(f"UTF-16LE string count: {stats.get('utf16le_string_count')}")
    lines.append(f"Unique combined string count: {stats.get('unique_combined_string_count')}")
    lines.append(f"Longest string length: {stats.get('longest_string_length')}")
    lines.append(f"Base64-like total count: {stats.get('base64_like_total_count')}")
    lines.append(f"Hex-like total count: {stats.get('hex_like_total_count')}")
    lines.append("")

    for label, key in [
        ("URLs", "urls"),
        ("IPv4 addresses", "ipv4"),
        ("Domains", "domains"),
        ("Emails", "emails"),
        ("Registry paths", "registry_paths"),
        ("Windows paths", "windows_paths"),
        ("UNC paths", "unc_paths"),
        ("Named pipes", "named_pipes"),
        ("PDB paths", "pdb_paths")
    ]:
        format_string_items(lines, label, strings.get(key, []))

    lines.append("")
    lines.append("Keyword hits:")

    for category, values in strings.get("keyword_hits", {}).items():
        lines.append(f"  {category}:")

        if values:
            for item in values:
                lines.append(f"    {preview(item.get('value'))} [{item.get('offset')}, {item.get('origin')}, {item.get('encoding')}]")
        else:
            lines.append("    None")

    lines.append("")
    lines.append("DECODED BASE64/HEX BLOB CANDIDATES")
    lines.append("-" * 80)

    if strings.get("encoded_blobs"):
        for blob in strings["encoded_blobs"]:
            lines.append(
                f"{blob.get('type')} at {blob.get('source_offset')} ({blob.get('source_origin')}): "
                f"decoded_size={blob.get('decoded_size')}, entropy={blob.get('decoded_entropy')}, "
                f"magic={blob.get('magic_hint')}, sha256={blob.get('decoded_sha256')}"
            )

            if blob.get("embedded_magic_hits"):
                lines.append(f"  Embedded magic: {blob.get('embedded_magic_hits')}")

            if blob.get("urls"):
                lines.append(f"  Decoded URLs: {', '.join(blob.get('urls'))}")

            if blob.get("domains"):
                lines.append(f"  Decoded domains: {', '.join(blob.get('domains'))}")

            if blob.get("ipv4"):
                lines.append(f"  Decoded IPv4: {blob.get('ipv4')}")

            if blob.get("sample_strings"):
                lines.append("  Sample decoded strings:")
                for value in blob.get("sample_strings", [])[:5]:
                    lines.append(f"    {value}")
    else:
        lines.append("No decodable base64/hex blob candidates with useful decoded content found")

    lines.append("")
    lines.append("IMPORT CAPABILITY HINTS")
    lines.append("-" * 80)
    imports = summary.get("imports", {})
    lines.append(f"Import table present: {imports.get('import_table_present')}")
    lines.append(f"DLL count: {imports.get('dll_count', 0)}")
    lines.append(f"Import count: {imports.get('import_count', 0)}")
    lines.append(f"Ordinal-only import count: {imports.get('ordinal_only_import_count', 0)}")

    if imports.get("api_combination_findings"):
        lines.append("")
        lines.append("API combination findings:")
        for finding in imports["api_combination_findings"]:
            format_finding(lines, finding)

    if imports.get("capability_imports"):
        lines.append("")
        for category, values in imports["capability_imports"].items():
            lines.append(f"{category}:")
            for value in values:
                lines.append(f"  {value}")
    else:
        lines.append("No categorized capability imports found")

    lines.append("")

    if imports.get("dlls"):
        lines.append("Imported DLLs:")
        lines.append(f"  {', '.join(imports['dlls'])}")
        lines.append("")

    lines.append("SECTIONS")
    lines.append("-" * 80)
    for section in summary.get("sections", []):
        flags = ", ".join(section["flags"]) if section["flags"] else "-"
        lines.append(
            f"{section['name']}: "
            f"VA={section['virtual_address']}, "
            f"VSIZE={section['virtual_size']}, "
            f"RAW={section['raw_pointer']}, "
            f"RAWEND={section['raw_end']}, "
            f"RAWSIZE={section['raw_size']}, "
            f"ENT={section['entropy']}, "
            f"SHA256={section['sha256']}, "
            f"FLAGS={flags}"
        )
    lines.append("")

    lines.append("SECTION LAYOUT ANOMALIES")
    lines.append("-" * 80)
    if summary.get("section_layout_anomalies"):
        for item in summary["section_layout_anomalies"]:
            lines.append(str(item))
    else:
        lines.append("None")
    lines.append("")

    lines.append("RESOURCES")
    lines.append("-" * 80)
    resources = summary.get("resources")

    if resources:
        by_type = resources.get("by_type", {})
        lines.append(f"Total resource data entries: {resources.get('resource_count', 0)}")
        lines.append("")
        lines.append("Resource type summary:")

        for rtype, info in by_type.items():
            lines.append(
                f"  {rtype}: count={info.get('count')}, "
                f"max_size={info.get('max_size')}, "
                f"max_entropy={info.get('max_entropy')}, "
                f"highest_priority={info.get('highest_priority')}"
            )

        resource_items = resources.get("items", [])

        if resource_items:
            lines.append("")
            lines.append("Resource entries:")

            for item in resource_items[:120]:
                reasons = "; ".join(item.get("priority_reasons", [])) or "-"
                lines.append(
                    f"  path={item.get('resource_path')}, raw_path={item.get('resource_raw_path')}, "
                    f"type={item.get('resource_type')}, name={item.get('resource_name')}, lang={item.get('resource_language')}, "
                    f"rva={item.get('rva')}, file_offset={item.get('file_offset')}, size={item.get('size')}, "
                    f"entropy={item.get('entropy')}, magic={item.get('magic_hint')}, priority={item.get('priority')}, "
                    f"reason={reasons}"
                )

            if len(resource_items) > 120:
                lines.append(f"  ... truncated {len(resource_items) - 120} additional resource entries")

        if resources.get("interesting_resources"):
            lines.append("")
            lines.append("Interesting resources:")
            for item in resources["interesting_resources"]:
                reasons = "; ".join(item.get("priority_reasons", [])) or "-"
                lines.append(
                    f"  path={item.get('resource_path')}, raw_path={item.get('resource_raw_path')}, "
                    f"type={item.get('resource_type')}, name={item.get('resource_name')}, lang={item.get('resource_language')}, "
                    f"rva={item.get('rva')}, file_offset={item.get('file_offset')}, "
                    f"size={item.get('size')}, entropy={item.get('entropy')}, priority={item.get('priority')}, "
                    f"reason={reasons}, magic={item.get('magic_hint')}, "
                    f"embedded_magic={item.get('embedded_magic_hits_compact')}, sha256={item.get('sha256')}"
                )
        else:
            lines.append("")
            lines.append("Interesting resources: None")
    else:
        lines.append("No resources found or resource table could not be parsed")

    lines.append("")
    lines.append("OVERLAY / TLS / CERTIFICATE / .NET")
    lines.append("-" * 80)
    lines.append(f"Overlay: {summary['overlay'] if summary['overlay'] else 'None'}")
    lines.append(f"TLS: {summary['tls'] if summary['tls'] else 'None'}")
    lines.append(f"Certificate: {summary['certificate']}")
    lines.append(f".NET: {summary['dotnet']}")
    lines.append("")

    lines.append("VERSION INFO")
    lines.append("-" * 80)
    if summary.get("version_info"):
        for key, value in sorted(summary["version_info"].items()):
            lines.append(f"{key}: {value}")
    else:
        lines.append("No version info found")
    lines.append("")

    lines.append("DEBUG / PDB")
    lines.append("-" * 80)
    if summary.get("debug"):
        for item in summary["debug"]:
            lines.append(f"Type: {item.get('type')}")
            lines.append(f"Timestamp UTC: {item.get('timestamp_utc')}")
            lines.append(f"Size: {item.get('size_of_data')}")
            if item.get("pdb_path"):
                lines.append(f"PDB path: {item['pdb_path']}")
    else:
        lines.append("No debug directory found")
    lines.append("")

    lines.append("RICH HEADER")
    lines.append("-" * 80)
    if summary.get("rich_header"):
        for key, value in summary["rich_header"].items():
            lines.append(f"{key}: {value}")
    else:
        lines.append("No Rich header found or not parsed")
    lines.append("")

    lines.append("DATA DIRECTORIES")
    lines.append("-" * 80)
    if summary.get("data_directories"):
        for directory in summary["data_directories"]:
            lines.append(f"{directory['name']}: RVA={directory['rva']}, size={directory['size']}")
    else:
        lines.append("No populated data directories")
    lines.append("")

    lines.append("DELAY IMPORTS")
    lines.append("-" * 80)
    if summary.get("delay_imports"):
        lines.append(f"DLL count: {summary['delay_imports']['dll_count']}")
        lines.append(f"DLLs: {', '.join(summary['delay_imports']['dlls'])}")

        if summary["delay_imports"].get("sample_imports"):
            lines.append(f"Sample imports: {', '.join(summary['delay_imports']['sample_imports'])}")
    else:
        lines.append("No delay imports found")
    lines.append("")

    lines.append("EXPORTS")
    lines.append("-" * 80)
    if summary.get("exports"):
        lines.append(f"DLL name: {summary['exports']['dll_name']}")
        lines.append(f"Export count: {summary['exports']['export_count']}")
        lines.append(f"Named export count: {summary['exports']['named_export_count']}")
        lines.append(f"Ordinal-only export count: {summary['exports']['ordinal_only_export_count']}")

        if summary["exports"]["sample_exports"]:
            lines.append(f"Sample exports: {', '.join(summary['exports']['sample_exports'])}")
    else:
        lines.append("No exports found")
    lines.append("")

    lines.append("HEADERS")
    lines.append("-" * 80)
    lines.append(f"DOS e_magic: {summary['dos_header'].get('e_magic')}")
    lines.append(f"DOS e_lfanew: {summary['dos_header'].get('e_lfanew')}")

    fh = summary["file_header"]
    lines.append(f"Machine: {fh.get('machine')} ({fh.get('machine_raw')})")
    lines.append(f"Sections: {fh.get('number_of_sections')}")
    lines.append(f"Compile timestamp UTC: {fh.get('timestamp_utc')}")
    lines.append(f"Compile timestamp raw: {fh.get('timestamp_raw')}")
    lines.append(f"Timestamp notes: {', '.join(fh.get('timestamp_notes', [])) if fh.get('timestamp_notes') else '-'}")
    lines.append(f"Characteristics: {', '.join(fh.get('characteristics', [])) if fh.get('characteristics') else '-'}")

    oh = summary["optional_header"]
    lines.append(f"PE magic: {oh.get('magic')}")
    lines.append(f"Linker version: {oh.get('linker_version')}")
    lines.append(f"Subsystem: {oh.get('subsystem')}")
    lines.append(f"Image base: {oh.get('image_base')}")
    lines.append(f"Size of image: {oh.get('size_of_image')}")
    lines.append(f"Size of headers: {oh.get('size_of_headers')}")
    lines.append(f"Section alignment: {oh.get('section_alignment')}")
    lines.append(f"File alignment: {oh.get('file_alignment')}")
    lines.append(f"OS version: {oh.get('os_version')}")
    lines.append(f"Subsystem version: {oh.get('subsystem_version')}")
    lines.append(f"DLL characteristics: {', '.join(oh.get('dll_characteristics', [])) if oh.get('dll_characteristics') else '-'}")
    lines.append("")

    lines.append("PARSER WARNINGS")
    lines.append("-" * 80)
    if summary.get("parser_warnings"):
        for warning in summary["parser_warnings"]:
            lines.append(f"- {warning}")
    else:
        lines.append("None")
    lines.append("")

    return "\n".join(lines)


def default_text_output_path(input_path):
    base = os.path.basename(input_path)
    stem = os.path.splitext(base)[0]

    return f"{stem}_pe_summary.txt"


def default_json_output_path(input_path):
    base = os.path.basename(input_path)
    stem = os.path.splitext(base)[0]

    return f"{stem}_pe_details.json"


def print_text_report(content):
    try:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        sys.stdout.buffer.write(content.encode(encoding, errors="replace"))
        if not content.endswith("\n"):
            sys.stdout.buffer.write(b"\n")


def main():
    parser = argparse.ArgumentParser(description="Create a PE malware triage report.")
    parser.add_argument("path", help="PE file to analyze")
    parser.add_argument("-o", "--output", metavar="PATH", help="text report path (default: <sample>_pe_summary.txt)")
    parser.add_argument("-j", "--json", action="store_true", help="also write detailed JSON report")
    parser.add_argument("--json-output", metavar="PATH", help="JSON report path (default: <sample>_pe_details.json)")
    parser.add_argument("-p", "--print", dest="print_text", action="store_true", help="print text report to console")
    args = parser.parse_args()

    try:
        summary = summarize(args.path)
    except pefile.PEFormatError as e:
        print(f"Not a valid PE file: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("File not found", file=sys.stderr)
        sys.exit(1)

    text_output_path = args.output or default_text_output_path(args.path)
    json_output_path = args.json_output or default_json_output_path(args.path)

    text_content = format_text(summary)

    with open(text_output_path, "w", encoding="utf-8") as f:
        f.write(text_content)

    if args.json_output and not args.json:
        args.json = True

    if args.json:
        json_content = json.dumps(summary, indent=2)

        with open(json_output_path, "w", encoding="utf-8") as f:
            f.write(json_content)

    if args.print_text:
        print_text_report(text_content)

    print(f"Wrote text report to: {text_output_path}", file=sys.stderr)

    if args.json:
        print(f"Wrote detailed JSON report to: {json_output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
