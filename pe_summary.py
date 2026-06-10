# pe_summary.py
# Malware PE triage summary using pefile.
# Intended for first-stage static triage, not full malware analysis.
# Dependency: pip install pefile
# Usage:
#   python pe_summary.py sample.exe
#   python pe_summary.py sample.exe -o report.txt
#   python pe_summary.py sample.exe --html-output report.html
#   python pe_summary.py sample.exe --json
#   python pe_summary.py sample.exe --json --json-output details.json
#   python pe_summary.py sample.exe --print
#   python pe_summary.py sample.exe --no-html
#
# Default output:
#   <sample>_pe_summary.txt
#   <sample>_pe_report.html

import argparse
import base64
import hashlib
import html
import ipaddress
import json
import math
import os
import time
import threading
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

LOW_SIGNAL_URL_HOST_SUFFIXES = (
    "wikipedia.org",
    "code.google.com",
    "chromium.org",
    "nodejs.org",
    "v8.dev",
    "marijnhaverbeke.nl",
    "schmorp.de",
    "ietf.org",
    "w3.org"
)

LOW_SIGNAL_URL_PATH_KEYWORDS = (
    "wiki", "sourcemap", "source-map", "documentation", "docs", "readme"
)

MAGIC_SIGNATURES = [
    (b"MZ", "PE/MZ"),
    (b"\x7fELF", "ELF"),
    (b"\x00asm", "WASM"),
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


RUNTIME_MARKERS = {
    "node_v8": [
        "node_sea_blob", "node.pdb", "node.exe", "node_modules", "lib/internal/",
        "process.versions.node", "napi_", "node_api", "v8::", "v8_", "v8_inspector",
        "__wbindgen", "wasm_", "__heap_base", "parsecjs"
    ],
    "electron_chromium": [
        "electron.asar", "app.asar", "electron_run_as_node", "chrome_100_percent.pak",
        "chromium", "blink", "v8_context", "devtools://", "icudtl.dat"
    ],
    "pyinstaller": [
        "_meipass", "pyiboot", "pyi_rth", "pyz-00.pyz", "pyinstaller"
    ],
    "go_runtime": [
        "go build id", "runtime.main", "runtime.gopanic", "runtime.makeslice", "gogo", "go.itab."
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
        "CryptUnprotectData", "CredEnumerateA", "CredEnumerateW", "CredReadA", "CredReadW",
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

class DelayedProgress:
    def __init__(self, total, label="Working", delay=1.5, enabled=True):
        self.total = max(total, 1)
        self.label = label
        self.delay = delay
        self.enabled = enabled and sys.stderr.isatty()
        self.start_time = time.monotonic()
        self.current = 0
        self.message = ""
        self.visible = False
        self.last_line = ""
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.spinner_index = 0
        self.spinner = "|/-\\"
        self.thread = None

    def start(self):
        if not self.enabled:
            return

        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def update(self, message):
        with self.lock:
            self.current = min(self.current + 1, self.total)
            self.message = message

    def _run(self):
        while not self.stop_event.is_set():
            elapsed = time.monotonic() - self.start_time

            if elapsed >= self.delay:
                self.visible = True
                self._render()

            time.sleep(0.15)

    def _render(self):
        with self.lock:
            width = 24
            ratio = min(self.current / self.total, 1.0)
            filled = int(width * ratio)
            bar = "#" * filled + "-" * (width - filled)
            percent = int(ratio * 100)
            spinner_char = self.spinner[self.spinner_index % len(self.spinner)]
            self.spinner_index += 1
            message = self.message or "Working..."

        line = f"\r{self.label} [{bar}] {percent:3d}% {spinner_char} {message}"
        padding = " " * max(0, len(self.last_line) - len(line))

        sys.stderr.write(line + padding)
        sys.stderr.flush()
        self.last_line = line

    def done(self):
        if self.thread:
            self.stop_event.set()
            self.thread.join(timeout=0.5)

        if self.visible:
            self._render()
            sys.stderr.write("\n")
            sys.stderr.flush()

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



def finding_sort_key(item):
    id_priority = {
        "entry_point_outside_sections": 0,
        "entry_point_high_entropy": 1,
        "section_execute_write": 2,
        "resource_node_sea_blob": 3,
        "overlay_non_certificate": 4,
        "encoded_blob_interesting": 5,
        "strings_network_indicators": 6,
        "api_process_dumping": 7,
        "api_downloader_execute": 8,
        "api_downloader_file_write": 9,
        "tls_present": 10,
        "resources_interesting": 11,
        "debug_pdb_path": 12,
        "runtime_heavy_bundle_detected": 13,
        "strings_large_noisy_corpus": 14,
    }

    return (
        severity_rank(item.get("severity")),
        confidence_rank(item.get("confidence")),
        id_priority.get(item.get("id"), 50),
        item.get("id", "")
    )


def confidence_value_rank(value):
    return {
        "high": 0,
        "medium": 1,
        "low": 2,
        "noise": 3,
        None: 4
    }.get(value, 4)


def string_item_sort_key(item):
    confidence = item.get("confidence")
    rank = confidence_value_rank(confidence)

    url_type_rank = 0
    if item.get("url_type") == "valid_url":
        url_type_rank = -1
    elif item.get("url_type") == "malformed_or_template_url":
        url_type_rank = 1

    ip_type_rank = 0
    if item.get("ip_type") == "public" and confidence in {"high", "medium"}:
        ip_type_rank = -1
    elif item.get("ip_type") in {"private", "loopback", "reserved", "multicast", "unspecified"}:
        ip_type_rank = 1

    origin_rank = 0
    origin = str(item.get("origin", ""))
    if origin.startswith("certificate_table"):
        origin_rank = 2
    elif origin.startswith("resource:"):
        origin_rank = 1

    return (
        rank,
        url_type_rank,
        ip_type_rank,
        origin_rank,
        item.get("offset_int", 0),
        str(item.get("value", "")).lower()
    )


def string_group_label(item):
    confidence = item.get("confidence")

    if confidence == "high":
        if item.get("url_type") == "valid_url":
            return "High confidence / valid"
        if item.get("context"):
            return "High confidence / contextual"
        return "High confidence"

    if confidence == "medium":
        return "Medium confidence / contextual"

    if confidence == "low":
        if item.get("url_type") == "malformed_or_template_url":
            return "Low confidence / malformed or template-like"
        return "Low confidence / weak"

    if confidence == "noise":
        return "Noise / allowlisted or certificate-related"

    return "Unscored"


def encoded_blob_sort_key(blob):
    assessment = blob.get("assessment", {})
    interesting_rank = 0 if assessment.get("interesting") else 1
    triage_rank = 0 if assessment.get("triage_interesting") else 1
    suspicious_rank = 0 if assessment.get("suspicious") else 1
    confidence = assessment.get("confidence")

    return (
        interesting_rank,
        triage_rank,
        suspicious_rank,
        confidence_rank(confidence),
        -(blob.get("decoded_size") or 0),
        blob.get("source_offset", "")
    )


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


def valid_hostname_or_ip(hostname):
    if not hostname:
        return False

    host = hostname.lower().strip(".")

    if host == "localhost":
        return True

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    if "%" in host or "_" in host:
        return False

    if host.startswith(".") or host.endswith("."):
        return False

    labels = host.split(".")

    if len(labels) < 2:
        return False

    if len(labels[-1]) < 2 or not labels[-1].isalpha():
        return False

    for label in labels:
        if not label or label.startswith("-") or label.endswith("-"):
            return False

        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False

    return True


def classify_url_candidate(value):
    cleaned = value.strip().rstrip(".,;:)]}'\"")

    try:
        parsed = urlparse(cleaned)
    except Exception:
        return {
            "value": value,
            "valid": False,
            "reason": "parse_error"
        }

    if parsed.scheme.lower() not in {"http", "https"}:
        return {
            "value": cleaned,
            "valid": False,
            "reason": "unsupported_scheme"
        }

    host = parsed.hostname

    if not host:
        return {
            "value": cleaned,
            "valid": False,
            "reason": "missing_host"
        }

    if not valid_hostname_or_ip(host):
        return {
            "value": cleaned,
            "valid": False,
            "reason": "invalid_or_template_host",
            "host": host
        }

    return {
        "value": cleaned,
        "valid": True,
        "reason": "valid_host",
        "host": host.lower().strip(".")
    }


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
        "http", "https", "url", "host", "hostname", "user-agent", "connect", "socket", "dns",
        "server", "gateway", "gate", "api", "post", "get", "authorization", "bearer",
        "websocket", "c2", "callback", "beacon", "download", "upload"
    ]

    if value.lower().startswith(("http://", "https://")):
        url_info = classify_url_candidate(value)

        if url_info.get("valid"):
            return "high"

        return "low"

    if any(term in lowered for term in terms):
        return "medium"

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

        if classification == "public" and network_context_score(value, source["value"]) in {"medium", "high"}:
            item["confidence"] = "high"
            item["context"] = "near_network_terms"
        else:
            item["confidence"] = "low"

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
        url_info = classify_url_candidate(value)
        item["value"] = url_info.get("value", value)
        item["preview"] = preview(item["value"])
        item["url_host"] = url_info.get("host")
        item["url_type"] = "valid_url" if url_info.get("valid") else "malformed_or_template_url"

        noise_reason = noisy_network_reason(item["value"], item.get("origin"))

        if noise_reason:
            item["confidence"] = "noise"
            item["noise_reason"] = noise_reason
        elif url_info.get("valid"):
            item["confidence"] = "high"
        else:
            item["confidence"] = "low"
            item["parse_reason"] = url_info.get("reason")

    else:
        item["confidence"] = "medium"

    results.setdefault(name, []).append(item)


def unique_string_items(items, max_items):
    result = []
    seen = set()

    for item in sorted(items, key=string_item_sort_key):
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




def runtime_marker_scan(string_entries, max_evidence_per_family=10):
    results = {}

    for family in RUNTIME_MARKERS:
        results[family] = {
            "count": 0,
            "evidence": []
        }

    for source in string_entries:
        value = source.get("value", "")
        lowered = value.lower()

        for family, markers in RUNTIME_MARKERS.items():
            matched_marker = None

            for marker in markers:
                if marker in lowered:
                    matched_marker = marker
                    break

            if not matched_marker:
                continue

            results[family]["count"] += 1

            if len(results[family]["evidence"]) < max_evidence_per_family:
                results[family]["evidence"].append({
                    "marker": matched_marker,
                    "value": preview(value),
                    "offset": hex(source.get("offset", 0)),
                    "encoding": source.get("encoding")
                })

    return {
        family: data for family, data in results.items()
        if data["count"] > 0
    }


def string_noise_profile(stats):
    ascii_count = stats.get("ascii_string_count", 0) or 0
    utf16_count = stats.get("utf16le_string_count", 0) or 0
    unique_count = stats.get("unique_combined_string_count", 0) or 0
    longest = stats.get("longest_string_length", 0) or 0
    base64_count = stats.get("base64_like_total_count", 0) or 0
    hex_count = stats.get("hex_like_total_count", 0) or 0
    reasons = []

    if ascii_count + utf16_count >= 100000:
        reasons.append("very large string corpus")

    if unique_count >= 100000:
        reasons.append("very high unique string count")

    if longest >= 500000:
        reasons.append("very long embedded string/blob")

    if base64_count >= 1000:
        reasons.append("many base64-like candidates")

    if hex_count >= 1000:
        reasons.append("many hex-like candidates")

    return {
        "is_large_noisy": bool(reasons),
        "reasons": reasons,
        "ascii_plus_utf16_count": ascii_count + utf16_count
    }


def decoded_string_runtime_markers(strings):
    joined = "\n".join(strings).lower()
    hits = []

    for family, markers in RUNTIME_MARKERS.items():
        for marker in markers:
            if marker in joined:
                hits.append(f"{family}:{marker}")

                if len(hits) >= 10:
                    return hits

    wasm_specific = ["__wbindgen", "__heap_base", "wasm_", "memory", "parsecjs"]

    for marker in wasm_specific:
        if marker in joined and marker not in hits:
            hits.append(f"wasm:{marker}")

    return hits[:10]


def assess_decoded_blob(item, decoded_strings):
    reasons = []
    content_type = "generic_decoded_data"
    runtime_hits = decoded_string_runtime_markers(decoded_strings)
    valid_urls = []

    for url in item.get("urls", []):
        url_info = classify_url_candidate(url)

        if url_info.get("valid") and not noisy_network_reason(url_info.get("value", url)):
            valid_urls.append(url_info.get("value", url))

    public_ips = [ip for ip in item.get("ipv4", []) if ip.get("type") == "public"]
    domains = [domain for domain in item.get("domains", []) if not noisy_network_reason(domain)]
    high_signal_magic = []
    magic_at_start = item.get("magic_hint")

    for hit in item.get("embedded_magic_hits", []):
        magic = hit.get("magic")

        if magic == "PE/MZ" and hit.get("valid_pe"):
            high_signal_magic.append(f"valid embedded PE at {hit.get('offset')}")
        elif magic in {"ELF", "ZIP", "7z", "RAR", "CAB", "OLE/CFB", "PDF"}:
            high_signal_magic.append(f"embedded {magic} at {hit.get('offset')}")
        elif magic == "GZIP" and magic_at_start == "GZIP":
            high_signal_magic.append("decoded blob starts with GZIP")

    if runtime_hits:
        reasons.append("runtime/WASM markers: " + ", ".join(runtime_hits[:5]))

    if magic_at_start == "WASM" or (runtime_hits and any("wasm" in hit.lower() or "__wbindgen" in hit.lower() for hit in runtime_hits)):
        content_type = "wasm_or_runtime_blob"
        if magic_at_start == "WASM":
            reasons.append("magic at decoded start: WASM")
        return {
            "content_type": content_type,
            "interesting": False,
            "triage_interesting": True,
            "suspicious": False,
            "confidence": "high" if magic_at_start == "WASM" else "medium",
            "reasons": reasons
        }

    if magic_at_start in {"PE/MZ", "ELF", "ZIP", "7z", "RAR", "CAB", "OLE/CFB", "PDF"}:
        high_signal_magic.insert(0, f"magic at decoded start: {magic_at_start}")

    if high_signal_magic:
        content_type = "embedded_file_or_payload_candidate"
        reasons.extend(high_signal_magic[:5])
        return {
            "content_type": content_type,
            "interesting": True,
            "triage_interesting": True,
            "suspicious": True,
            "confidence": "high" if any("valid embedded PE" in reason for reason in high_signal_magic) else "medium",
            "reasons": reasons
        }

    if valid_urls or domains or public_ips:
        content_type = "indicator_or_config_candidate"
        reasons.append(
            f"decoded indicators: urls={len(valid_urls)}, domains={len(domains)}, public_ipv4={len(public_ips)}"
        )
        return {
            "content_type": content_type,
            "interesting": True,
            "triage_interesting": True,
            "suspicious": False,
            "confidence": "medium",
            "reasons": reasons
        }

    if item.get("decoded_entropy", 0) >= 7.2 and item.get("decoded_size", 0) >= 1024 and not runtime_hits:
        content_type = "compressed_or_encrypted_candidate"
        reasons.append("high entropy decoded data")
        return {
            "content_type": content_type,
            "interesting": True,
            "triage_interesting": True,
            "suspicious": False,
            "confidence": "medium",
            "reasons": reasons
        }

    if runtime_hits:
        return {
            "content_type": "runtime_or_library_data",
            "interesting": False,
            "triage_interesting": True,
            "suspicious": False,
            "confidence": "medium",
            "reasons": reasons
        }

    return {
        "content_type": content_type,
        "interesting": False,
        "triage_interesting": False,
        "suspicious": False,
        "confidence": "low",
        "reasons": reasons
    }

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

    item = {
        "type": blob_type,
        "decoded_size": len(decoded),
        "decoded_entropy": round(entropy(decoded), 2),
        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
        "magic_hint": magic_hint(decoded),
        "embedded_magic_hits": find_magic_hits(decoded[:MAX_MAGIC_SCAN_BYTES], limit=10),
        "urls": urls,
        "ipv4": ipv4,
        "domains": domains,
        "sample_strings": [preview(value, 100) for value in strings[:10]]
    }
    item["assessment"] = assess_decoded_blob(item, strings)
    item["interesting"] = item["assessment"].get("interesting", False)
    item["content_type"] = item["assessment"].get("content_type")

    return item

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
    results["runtime_markers"] = runtime_marker_scan(string_entries)
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
    results["string_noise_profile"] = string_noise_profile(results["stats"])

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
    urls = [item for item in strings.get("urls", []) if item.get("confidence") in {"medium", "high"}]
    low_urls = [item for item in strings.get("urls", []) if item.get("confidence") == "low"]
    noisy_urls = [item for item in strings.get("urls", []) if item.get("confidence") == "noise"]
    public_ips = [item for item in strings.get("ipv4", []) if item.get("ip_type") == "public" and item.get("confidence") in {"medium", "high"}]
    low_public_ips = [item for item in strings.get("ipv4", []) if item.get("ip_type") == "public" and item.get("confidence") == "low"]
    medium_high_domains = [item for item in strings.get("domains", []) if item.get("confidence") in {"medium", "high"}]
    low_domains = [item for item in strings.get("domains", []) if item.get("confidence") == "low"]
    noisy_domains = [item for item in strings.get("domains", []) if item.get("confidence") == "noise"]

    return {
        "urls": len(urls),
        "low_confidence_urls": len(low_urls),
        "public_ipv4": len(public_ips),
        "low_confidence_public_ipv4": len(low_public_ips),
        "medium_high_domains": len(medium_high_domains),
        "low_confidence_domains": len(low_domains),
        "noisy_urls": len(noisy_urls),
        "noisy_domains": len(noisy_domains)
    }




def runtime_marker_evidence(strings, family, limit=5):
    markers = strings.get("runtime_markers", {}).get(family, {})
    evidence = []

    for item in markers.get("evidence", [])[:limit]:
        evidence.append(f"{item.get('marker')} at {item.get('offset')}: {item.get('value')}")

    return evidence


def resource_name_contains(resources, text):
    text_lower = text.lower()
    matches = []

    if not resources:
        return matches

    for item in resources.get("items", []):
        joined = " ".join(str(item.get(key, "")) for key in [
            "resource_path", "resource_raw_path", "resource_type", "resource_name"
        ]).lower()

        if text_lower in joined:
            matches.append(item)

    return matches


def all_visible_string_values(summary):
    values = []
    strings = summary.get("strings", {})

    for key in ["urls", "domains", "emails", "registry_paths", "windows_paths", "unc_paths", "named_pipes", "pdb_paths"]:
        for item in strings.get(key, []):
            if item.get("value"):
                values.append(str(item.get("value")))

    for category_values in strings.get("keyword_hits", {}).values():
        for item in category_values:
            if item.get("value"):
                values.append(str(item.get("value")))

    for item in summary.get("key_artifacts", []):
        if item.get("value"):
            values.append(str(item.get("value")))

    return values


def visible_strings_contain(summary, terms):
    joined = "\n".join(all_visible_string_values(summary)).lower()
    return any(term.lower() in joined for term in terms)




def is_low_signal_reference_url(item):
    value = item.get("value", "") if isinstance(item, dict) else str(item)
    info = classify_url_candidate(value)

    if not info.get("valid"):
        return True

    host = (info.get("host") or "").lower().strip(".")

    if host in {"localhost", "127.0.0.1", "0.0.0.0"}:
        return True

    if any(host == suffix or host.endswith("." + suffix) for suffix in LOW_SIGNAL_URL_HOST_SUFFIXES):
        return True

    try:
        path = urlparse(info.get("value", value)).path.lower()
    except Exception:
        path = ""

    if any(keyword in path for keyword in LOW_SIGNAL_URL_PATH_KEYWORDS):
        return True

    return False

def strong_network_evidence(summary):
    strings = summary.get("strings", {})
    runtime = summary.get("runtime_context", {})
    actionable_urls = [
        item for item in strings.get("urls", [])
        if item.get("confidence") in {"medium", "high"} and not is_low_signal_reference_url(item)
    ]
    actionable_domains = [
        item for item in strings.get("domains", [])
        if item.get("confidence") in {"medium", "high", "high"} and not noisy_network_reason(item.get("value", ""), item.get("origin"))
    ]

    if actionable_urls:
        return True

    if runtime.get("is_runtime_heavy"):
        return False

    if actionable_domains:
        return True

    contextual_public_ips = [
        item for item in strings.get("ipv4", [])
        if item.get("ip_type") == "public" and item.get("confidence") in {"medium", "high"}
    ]

    return bool(contextual_public_ips)


def process_dump_targeting_evidence(summary):
    return visible_strings_contain(summary, [
        "lsass", "lsass.exe", "minidump", "procdump", "sedebugprivilege", "comsvcs.dll"
    ])


def detect_runtime_context(summary):
    resources = summary.get("resources") or {}
    strings = summary.get("strings", {})
    imports = summary.get("imports", {})
    delay_imports = summary.get("delay_imports") or {}
    file_size = summary.get("file", {}).get("size_bytes", 0) or 0
    stats = strings.get("stats", {})
    families = []

    node_evidence = []

    for item in resource_name_contains(resources, "NODE_SEA_BLOB"):
        node_evidence.append(f"resource {item.get('resource_path')} size={item.get('size')}")

    for dll in delay_imports.get("dlls", []):
        if str(dll).lower() == "node.exe":
            node_evidence.append("delay import node.exe")

    for item in summary.get("debug", []):
        if "node.pdb" in str(item.get("pdb_path", "")).lower():
            node_evidence.append(f"debug PDB {item.get('pdb_path')}")

    for item in strings.get("pdb_paths", []):
        if "node.pdb" in str(item.get("value", "")).lower():
            node_evidence.append(f"PDB string {item.get('value')}")

    node_marker_count = strings.get("runtime_markers", {}).get("node_v8", {}).get("count", 0)

    if node_marker_count:
        node_evidence.append(f"node/v8 runtime string markers={node_marker_count}")
        node_evidence.extend(runtime_marker_evidence(strings, "node_v8", limit=4))

    if node_evidence:
        families.append({
            "name": "node_v8_or_node_sea",
            "confidence": "high" if resource_name_contains(resources, "NODE_SEA_BLOB") or node_marker_count >= 5 else "medium",
            "evidence": dedupe_keep_order(node_evidence)[:10]
        })

    electron_evidence = []
    electron_marker_count = strings.get("runtime_markers", {}).get("electron_chromium", {}).get("count", 0)

    if electron_marker_count:
        electron_evidence.append(f"electron/chromium markers={electron_marker_count}")
        electron_evidence.extend(runtime_marker_evidence(strings, "electron_chromium", limit=5))

    if electron_evidence:
        families.append({
            "name": "electron_or_chromium_bundle",
            "confidence": "medium",
            "evidence": dedupe_keep_order(electron_evidence)[:10]
        })

    pyinstaller_evidence = []
    pyinstaller_marker_count = strings.get("runtime_markers", {}).get("pyinstaller", {}).get("count", 0)

    if pyinstaller_marker_count:
        pyinstaller_evidence.append(f"pyinstaller markers={pyinstaller_marker_count}")
        pyinstaller_evidence.extend(runtime_marker_evidence(strings, "pyinstaller", limit=5))

    if pyinstaller_evidence:
        families.append({
            "name": "pyinstaller_bundle",
            "confidence": "medium",
            "evidence": dedupe_keep_order(pyinstaller_evidence)[:10]
        })

    go_evidence = []
    go_marker_count = strings.get("runtime_markers", {}).get("go_runtime", {}).get("count", 0)

    if go_marker_count:
        go_evidence.append(f"go runtime markers={go_marker_count}")
        go_evidence.extend(runtime_marker_evidence(strings, "go_runtime", limit=5))

    if go_evidence:
        families.append({
            "name": "go_runtime",
            "confidence": "medium",
            "evidence": dedupe_keep_order(go_evidence)[:10]
        })

    string_noise = strings.get("string_noise_profile", {})
    large_runtime_shape = (
        file_size >= 20 * 1024 * 1024 or
        (stats.get("ascii_string_count", 0) or 0) + (stats.get("utf16le_string_count", 0) or 0) >= 100000 or
        imports.get("import_count", 0) >= 300
    )

    return {
        "detected": bool(families),
        "is_runtime_heavy": bool(families and large_runtime_shape),
        "families": families,
        "large_runtime_shape": large_runtime_shape,
        "string_noise_profile": string_noise,
        "notes": [
            "Generic imports and strings may reflect bundled runtime capability rather than sample-specific behavior."
        ] if families and large_runtime_shape else []
    }


def adjust_api_finding_for_context(finding, summary):
    runtime = summary.get("runtime_context", {})

    if not runtime.get("is_runtime_heavy"):
        return finding

    finding_id = finding.get("id")
    adjusted = dict(finding)
    adjusted["evidence"] = list(finding.get("evidence", []))
    adjusted["context_adjusted"] = True
    adjusted["original_severity"] = finding.get("severity")
    adjusted["original_confidence"] = finding.get("confidence")

    context_note = "large bundled/runtime-heavy binary detected; import may reflect runtime capability"

    if finding_id in {"api_downloader_file_write", "api_downloader_execute"} and not strong_network_evidence(summary):
        adjusted["severity"] = "medium" if finding.get("severity") == "high" else "low"
        adjusted["confidence"] = "low"
        adjusted["title"] = finding.get("title", "API finding") + " (runtime-capability context)"
        adjusted["evidence"].append(context_note)
        adjusted["recommendation"] = "Treat as weak until concrete URL/C2/config or downloaded-execution logic is found."
        return adjusted

    if finding_id == "api_process_dumping" and not process_dump_targeting_evidence(summary):
        adjusted["severity"] = "medium"
        adjusted["confidence"] = "low"
        adjusted["title"] = "Process dumping import (runtime-capability context)"
        adjusted["evidence"].append(context_note)
        adjusted["recommendation"] = "Treat as capability only unless LSASS/process-dump targeting evidence is present."
        return adjusted

    if finding_id == "api_dynamic_resolution":
        adjusted["severity"] = "low"
        adjusted["confidence"] = "low"
        adjusted["title"] = "Dynamic API resolution imports (common in bundled runtimes)"
        adjusted["evidence"].append(context_note)
        adjusted["recommendation"] = "Keep as context; prioritize resolved suspicious API-name strings instead."
        return adjusted

    if finding_id == "api_anti_debugging":
        adjusted["confidence"] = "low"
        adjusted["evidence"].append(context_note)
        return adjusted

    return finding


def adjust_api_combination_findings_for_context(summary):
    imports = summary.get("imports", {})
    findings = imports.get("api_combination_findings", [])

    if not findings:
        return

    imports["api_combination_findings"] = sorted(
        [adjust_api_finding_for_context(finding, summary) for finding in findings],
        key=finding_sort_key
    )

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
    runtime_context = summary.get("runtime_context", {})

    if runtime_context.get("is_runtime_heavy"):
        evidence = []

        for family in runtime_context.get("families", [])[:4]:
            evidence.append(f"{family.get('name')} ({family.get('confidence')} confidence)")

            for item in family.get("evidence", [])[:3]:
                evidence.append(item)

        add_finding(
            findings,
            "runtime_heavy_bundle_detected",
            "info",
            "high",
            "Runtime-heavy or bundled binary detected",
            evidence[:10],
            "Treat generic imports and broad string hits as runtime capability until supported by concrete sample-specific evidence."
        )

    if strings.get("string_noise_profile", {}).get("is_large_noisy"):
        add_finding(
            findings,
            "strings_large_noisy_corpus",
            "info",
            "high",
            "Large/noisy string corpus detected",
            strings.get("string_noise_profile", {}).get("reasons", []),
            "Prioritize high-confidence URLs, validated embedded files, resources, and config-like strings over broad regex hits."
        )

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

    node_sea_resources = resource_name_contains(resources, "NODE_SEA_BLOB") if resources else []

    if node_sea_resources:
        evidence = []

        for item in node_sea_resources[:5]:
            evidence.append(
                f"path={item.get('resource_path')}, size={item.get('size')}, entropy={item.get('entropy')}, "
                f"file_offset={item.get('file_offset')}"
            )

        add_finding(
            findings,
            "resource_node_sea_blob",
            "medium",
            "high",
            "Node SEA blob resource found",
            evidence,
            "Extract and inspect the Node SEA blob / embedded JavaScript content."
        )

    if resources and resources.get("interesting_resources"):
        covered_resource_paths = set()

        if node_sea_resources:
            covered_resource_paths.update(item.get("resource_path") for item in node_sea_resources if item.get("resource_path"))

        uncovered_interesting = [
            item for item in resources.get("interesting_resources", [])
            if item.get("resource_path") not in covered_resource_paths
        ]

        if uncovered_interesting:
            high_resources = [item for item in uncovered_interesting if item.get("priority") == "high"]
            severity = "high" if high_resources else "medium"
            evidence = []

            for item in uncovered_interesting[:10]:
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
    runtime_blob_evidence = []
    encoded_severity = "medium"
    encoded_confidence = "medium"

    for blob in encoded_blobs:
        assessment = blob.get("assessment", {})
        reasons = "; ".join(assessment.get("reasons", [])[:3]) or "decoded content"
        evidence_text = (
            f"{blob.get('type')} at {blob.get('source_offset')} origin={blob.get('source_origin')} "
            f"content_type={assessment.get('content_type')} size={blob.get('decoded_size')} "
            f"suspicious={assessment.get('suspicious')} reason={reasons}"
        )

        if assessment.get("interesting"):
            encoded_evidence.append(evidence_text)

            if assessment.get("confidence") == "high":
                encoded_severity = "high"
                encoded_confidence = "high"
        elif assessment.get("triage_interesting"):
            runtime_blob_evidence.append(evidence_text)

    if encoded_evidence:
        add_finding(
            findings,
            "encoded_blob_interesting",
            encoded_severity,
            encoded_confidence,
            "Encoded blob decodes to potentially actionable content",
            encoded_evidence[:10],
            "Review decoded blob output and carve it if it contains validated embedded files, config, or indicators."
        )

    if runtime_blob_evidence:
        add_finding(
            findings,
            "encoded_blob_runtime_or_wasm",
            "info",
            "high",
            "Decoded runtime/WASM blob found",
            runtime_blob_evidence[:10],
            "Useful for understanding the bundled runtime; do not treat as suspicious without additional evidence."
        )

    counts = network_indicator_counts(strings)

    if counts["urls"] or counts["public_ipv4"] or counts["medium_high_domains"]:
        evidence = [
            f"valid_urls={counts['urls']}",
            f"public_ipv4_with_network_context={counts['public_ipv4']}",
            f"medium_high_domains={counts['medium_high_domains']}",
            f"low_confidence_urls={counts['low_confidence_urls']}",
            f"low_confidence_public_ipv4={counts['low_confidence_public_ipv4']}",
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

    ordered = sorted(findings, key=finding_sort_key)

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

    if "runtime_heavy_bundle_detected" in ids:
        steps.append("Account for bundled-runtime noise before treating generic imports or broad strings as behavior")

    if "encoded_blob_interesting" in ids:
        steps.append("Review decoded base64/hex blob output and carve decoded payloads if useful")

    if "resource_node_sea_blob" in ids:
        steps.append("Extract and inspect the Node SEA blob / embedded JavaScript content")

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
    summary["runtime_context"] = module_run("runtime_context", lambda: detect_runtime_context(summary), {}, warnings)
    adjust_api_combination_findings_for_context(summary)
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

    lines.append("SUMMARY")
    lines.append("-" * 80)
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

    runtime = summary.get("runtime_context", {})

    if runtime.get("detected"):
        family_names = ", ".join(family.get("name") for family in runtime.get("families", [])[:3])
        heavy_text = "runtime-heavy" if runtime.get("is_runtime_heavy") else "runtime markers"
        lines.append(f"Runtime context: {heavy_text} ({family_names})")

    if summary.get("dotnet", {}).get("is_dotnet"):
        lines.append("Runtime: .NET/CLR header present")

    if summary.get("overlay"):
        overlay = summary["overlay"]
        lines.append(f"Overlay: {overlay.get('classification')}, size={overlay.get('size')}, entropy={overlay.get('entropy')}")

    counts = network_indicator_counts(summary.get("strings", {}))
    lines.append(
        "String network candidates: "
        f"valid_urls={counts['urls']}, contextual_public_ipv4={counts['public_ipv4']}, "
        f"medium_high_domains={counts['medium_high_domains']}, low_urls={counts['low_confidence_urls']}, "
        f"low_public_ipv4={counts['low_confidence_public_ipv4']}, low_domains={counts['low_confidence_domains']}, "
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

    if not values:
        lines.append("  None")
        return

    ordered_values = sorted(values, key=string_item_sort_key)
    groups = []
    current_label = None
    current_items = []

    for item in ordered_values:
        group_label = string_group_label(item)

        if current_label is None:
            current_label = group_label

        if group_label != current_label:
            groups.append((current_label, current_items))
            current_label = group_label
            current_items = []

        current_items.append(item)

    if current_items:
        groups.append((current_label, current_items))

    if len(groups) == 1:
        for item in groups[0][1]:
            format_single_string_item(lines, item, indent="  ")
        return

    for group_label, group_items in groups:
        lines.append(f"  {group_label}:")

        for item in group_items:
            format_single_string_item(lines, item, indent="    ")


def format_single_string_item(lines, item, indent="  "):
    confidence = item.get("confidence")
    suffix_parts = [item.get("offset"), item.get("origin"), item.get("encoding")]

    if confidence:
        suffix_parts.append(f"confidence={confidence}")

    if item.get("ip_type"):
        suffix_parts.append(f"type={item.get('ip_type')}")

    if item.get("url_type"):
        suffix_parts.append(item.get("url_type"))

    if item.get("context"):
        suffix_parts.append(f"context={item.get('context')}")

    if item.get("parse_reason"):
        suffix_parts.append(f"parse={item.get('parse_reason')}")

    if item.get("noise_reason"):
        suffix_parts.append(f"noise={item.get('noise_reason')}")

    suffix = ", ".join(str(x) for x in suffix_parts if x)
    lines.append(f"{indent}{preview(item.get('value'))} [{suffix}]")


def format_text(summary):
    lines = []
    file_info = summary["file"]
    hashes = summary["hashes"]

    lines.append("PE TRIAGE SUMMARY")
    lines.append("=" * 80)
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

    lines.append("RUNTIME / BUNDLE CONTEXT")
    lines.append("-" * 80)
    runtime = summary.get("runtime_context", {})

    if runtime.get("detected"):
        lines.append(f"Runtime-heavy: {runtime.get('is_runtime_heavy')}")

        for family in runtime.get("families", []):
            lines.append(f"{family.get('name')}: confidence={family.get('confidence')}")

            for evidence in family.get("evidence", [])[:5]:
                lines.append(f"  {preview(evidence)}")

        if runtime.get("notes"):
            for note in runtime.get("notes"):
                lines.append(f"Note: {note}")
    else:
        lines.append("No bundled-runtime context detected")

    noise_profile = summary.get("strings", {}).get("string_noise_profile", {})

    if noise_profile.get("is_large_noisy"):
        lines.append("String noise profile: " + ", ".join(noise_profile.get("reasons", [])))

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
        for blob in sorted(strings["encoded_blobs"], key=encoded_blob_sort_key):
            lines.append(
                f"{blob.get('type')} at {blob.get('source_offset')} ({blob.get('source_origin')}): "
                f"decoded_size={blob.get('decoded_size')}, entropy={blob.get('decoded_entropy')}, "
                f"magic={blob.get('magic_hint')}, sha256={blob.get('decoded_sha256')}"
            )

            if blob.get("assessment"):
                assessment = blob.get("assessment", {})
                reason_text = "; ".join(assessment.get("reasons", [])) or "-"
                lines.append(
                    f"  Assessment: content_type={assessment.get('content_type')}, "
                    f"interesting={assessment.get('interesting')}, "
                    f"triage_interesting={assessment.get('triage_interesting')}, "
                    f"suspicious={assessment.get('suspicious')}, "
                    f"confidence={assessment.get('confidence')}, reason={preview(reason_text, 180)}"
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
        for finding in sorted(imports["api_combination_findings"], key=finding_sort_key):
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


def default_html_output_path(input_path):
    base = os.path.basename(input_path)
    stem = os.path.splitext(base)[0]

    return f"{stem}_pe_report.html"


def html_escape(value):
    if value is None:
        return ""

    return html.escape(str(value), quote=True)


def html_id(value):
    value = str(value or "section").lower()
    value = re.sub(r"[^a-z0-9]+", "-", value).strip("-")

    return value or "section"


def html_scalar(value):
    if value is None:
        return "-"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, (list, tuple, set)):
        if not value:
            return "-"

        return ", ".join(str(item) for item in value)

    if isinstance(value, dict):
        if not value:
            return "-"

        return json.dumps(value, sort_keys=True)

    return str(value)


def html_badge(value, kind="generic"):
    if value is None or value == "":
        return '<span class="badge muted">-</span>'

    text = str(value)
    css_value = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "value"
    classes = f"badge {kind} {kind}-{css_value}"

    return f'<span class="{html_escape(classes)}">{html_escape(text)}</span>'


def html_severity_badges(severity, confidence=None):
    result = html_badge(str(severity or "info").upper(), "severity")

    if confidence:
        result += " " + html_badge(confidence, "confidence")

    return result


def html_flags(flags):
    if not flags:
        return '<span class="muted">-</span>'

    return " ".join(html_badge(flag, "flag") for flag in flags)


def html_kv(rows):
    body = []

    for key, value in rows:
        body.append(
            "<tr>"
            f"<th>{html_escape(key)}</th>"
            f"<td>{html_escape(html_scalar(value))}</td>"
            "</tr>"
        )

    return '<table class="kv"><tbody>' + "".join(body) + "</tbody></table>"


def html_table(headers, rows):
    if not rows:
        return '<p class="muted">None</p>'

    head = "".join(f"<th>{html_escape(header)}</th>" for header in headers)
    body = []

    for row in rows:
        body.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")

    return (
        '<div class="table-wrap"><table class="data-table searchable-table">'
        f"<thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(body)}</tbody>"
        "</table></div>"
    )


def html_status_badge(label, value=None, state="content"):
    text = str(label) if value is None else f"{label}: {value}"
    state_value = re.sub(r"[^a-z0-9]+", "-", str(state).lower()).strip("-") or "content"

    return f'<span class="status-badge status-{html_escape(state_value)}">{html_escape(text)}</span>'


def pluralize(count, singular, plural=None):
    if plural is None:
        plural = singular + "s"

    return f"{count} {singular if count == 1 else plural}"


def html_section(title, content, open_by_default=True, section_id=None, meta=None):
    section_id = html_id(section_id or title)
    open_attr = " open" if open_by_default else ""
    meta_html = ""

    if meta:
        if isinstance(meta, (list, tuple)):
            meta_html = "".join(str(item) for item in meta if item)
        else:
            meta_html = str(meta)

    if meta_html:
        summary = (
            '<summary>'
            f'<span class="summary-title">{html_escape(title)}</span>'
            f'<span class="summary-meta">{meta_html}</span>'
            '</summary>'
        )
    else:
        summary = f'<summary><span class="summary-title">{html_escape(title)}</span></summary>'

    return (
        f'<details class="section" id="{section_id}"{open_attr}>'
        f'{summary}'
        f'<div class="section-body">{content}</div>'
        '</details>'
    )


def html_nav(title):
    return f'<a href="#{html_id(title)}">{html_escape(title)}</a>'


def count_non_noise_strings(strings, key):
    return sum(
        1 for item in strings.get(key, [])
        if item.get("confidence") != "noise"
    )


def html_section_meta(summary, title, visible_limit=None):
    findings = summary.get("findings", [])
    severity_counts = {
        "high": sum(1 for item in findings if item.get("severity") == "high"),
        "medium": sum(1 for item in findings if item.get("severity") == "medium"),
        "low": sum(1 for item in findings if item.get("severity") == "low"),
        "info": sum(1 for item in findings if item.get("severity") == "info"),
    }

    if title == "Overview":
        return [html_status_badge("dashboard", state="content")]

    if title == "Metadata and headers":
        warning_count = len(summary.get("parser_warnings", []))
        badges = [html_status_badge("identity", state="content"), html_status_badge("headers", state="content")]

        if summary.get("version_info"):
            badges.append(html_status_badge("version", state="content"))

        if summary.get("debug"):
            badges.append(html_status_badge("debug", len(summary.get("debug", [])), state="content"))

        if warning_count:
            badges.append(html_status_badge("warnings", warning_count, state="warning"))

        return badges

    if title == "Top findings":
        shown = min(visible_limit or 5, len(findings))

        if not findings:
            return [html_status_badge("empty", state="empty")]

        badges = [html_status_badge("shown", f"{shown}/{len(findings)}", state="content")]

        if severity_counts["high"]:
            badges.append(html_status_badge("high", severity_counts["high"], state="high"))

        if severity_counts["medium"]:
            badges.append(html_status_badge("medium", severity_counts["medium"], state="medium"))

        return badges

    if title == "All findings":
        if not findings:
            return [html_status_badge("empty", state="empty")]

        badges = [html_status_badge("total", len(findings), state="content")]

        for severity in ["high", "medium", "low", "info"]:
            if severity_counts[severity]:
                badges.append(html_status_badge(severity, severity_counts[severity], state=severity))

        return badges

    if title == "Recommended next steps":
        count = len(summary.get("recommended_next_steps", []))
        return [html_status_badge(pluralize(count, "step"), state="content" if count else "empty")]

    if title == "Key artifacts":
        count = len(summary.get("key_artifacts", []))
        return [html_status_badge(pluralize(count, "artifact"), state="content" if count else "empty")]

    if title == "Runtime context":
        runtime = summary.get("runtime_context", {})

        if not runtime.get("detected"):
            return [html_status_badge("not detected", state="empty")]

        family_count = len(runtime.get("families", []))
        badges = [html_status_badge("detected", state="content")]
        badges.append(html_status_badge(pluralize(family_count, "family", "families"), state="content"))

        if runtime.get("is_runtime_heavy"):
            badges.append(html_status_badge("runtime-heavy", state="warning"))

        return badges

    if title == "Imports":
        imports = summary.get("imports", {})
        import_count = imports.get("import_count", 0) or 0
        dll_count = imports.get("dll_count", 0) or 0
        combo_count = len(imports.get("api_combination_findings", []))
        badges = [html_status_badge("DLLs", dll_count, state="content" if dll_count else "empty")]
        badges.append(html_status_badge("imports", import_count, state="content" if import_count else "empty"))

        if combo_count:
            badges.append(html_status_badge("API combos", combo_count, state="warning"))

        return badges

    if title == "Sections":
        sections = summary.get("sections", [])
        flagged = sum(1 for section in sections if section.get("flags"))
        high_entropy = sum(1 for section in sections if "HIGH_ENTROPY" in section.get("flags", []))
        badges = [html_status_badge(pluralize(len(sections), "section"), state="content" if sections else "empty")]

        if flagged:
            badges.append(html_status_badge("flagged", flagged, state="warning"))

        if high_entropy:
            badges.append(html_status_badge("high entropy", high_entropy, state="warning"))

        return badges

    if title == "Resources":
        resources = summary.get("resources") or {}
        resource_count = resources.get("resource_count", 0) or 0
        interesting_count = len(resources.get("interesting_resources", []))
        badges = [html_status_badge(pluralize(resource_count, "resource"), state="content" if resource_count else "empty")]

        if interesting_count:
            badges.append(html_status_badge("interesting", interesting_count, state="warning"))

        return badges

    if title == "Overlay / TLS / certificate / .NET":
        overlay = summary.get("overlay")
        tls = summary.get("tls")
        certificate = summary.get("certificate") or {}
        dotnet = summary.get("dotnet") or {}
        badges = []
        badges.append(html_status_badge("overlay", "present" if overlay else "none", state="warning" if overlay else "empty"))
        badges.append(html_status_badge("TLS", "present" if tls else "none", state="warning" if tls else "empty"))
        badges.append(html_status_badge("cert", "present" if certificate.get("present") else "none", state="content" if certificate.get("present") else "empty"))
        badges.append(html_status_badge(".NET", "yes" if dotnet.get("is_dotnet") else "no", state="content" if dotnet.get("is_dotnet") else "empty"))

        return badges

    if title == "Interesting strings":
        strings = summary.get("strings", {})
        candidate_count = sum(
            count_non_noise_strings(strings, key)
            for key in ["urls", "ipv4", "domains", "emails", "registry_paths", "windows_paths", "unc_paths", "named_pipes", "pdb_paths"]
        )
        badges = [html_status_badge("candidates", candidate_count, state="content" if candidate_count else "empty")]
        url_count = count_non_noise_strings(strings, "urls")
        domain_count = count_non_noise_strings(strings, "domains")
        ip_count = count_non_noise_strings(strings, "ipv4")

        if url_count:
            badges.append(html_status_badge("URLs", url_count, state="warning"))

        if domain_count:
            badges.append(html_status_badge("domains", domain_count, state="warning"))

        if ip_count:
            badges.append(html_status_badge("IPv4", ip_count, state="warning"))

        return badges

    if title == "Decoded blobs":
        blobs = summary.get("strings", {}).get("encoded_blobs", [])
        interesting = sum(1 for blob in blobs if (blob.get("assessment") or {}).get("interesting"))
        badges = [html_status_badge(pluralize(len(blobs), "candidate"), state="content" if blobs else "empty")]

        if interesting:
            badges.append(html_status_badge("interesting", interesting, state="warning"))

        return badges

    if title == "Raw text report":
        return [html_status_badge("plain text", state="content")]

    if title == "Raw JSON":
        return [html_status_badge("full structured data", state="content")]

    return []


def html_best_finding(summary):
    findings = summary.get("findings", [])

    if not findings:
        return None

    return sorted(findings, key=finding_sort_key)[0]


def html_overview(summary):
    file_info = summary.get("file", {})
    hashes = summary.get("hashes", {})
    file_header = summary.get("file_header", {})
    optional = summary.get("optional_header", {})
    entry_point = summary.get("entry_point", {})
    imports = summary.get("imports", {})
    resources = summary.get("resources") or {}
    overlay = summary.get("overlay") or {}
    runtime = summary.get("runtime_context", {})
    finding = html_best_finding(summary)
    ep_text = entry_point.get("entry_point_rva", "-")

    if entry_point.get("section"):
        ep_text += f" in {entry_point.get('section')}"

    if entry_point.get("section_entropy") is not None:
        ep_text += f" / entropy {entry_point.get('section_entropy')}"

    runtime_text = "not detected"

    if runtime.get("detected"):
        runtime_text = ", ".join(
            family.get("name", "runtime")
            for family in runtime.get("families", [])[:4]
        )

        if runtime.get("is_runtime_heavy"):
            runtime_text += " / runtime-heavy"

    highest_html = '<span class="muted">No structured findings</span>'

    if finding:
        highest_html = (
            html_severity_badges(finding.get("severity"), finding.get("confidence"))
            + f' <span>{html_escape(finding.get("title"))}</span>'
        )

    cards = [
        ("File", html_escape(file_info.get("name"))),
        ("Size", html_escape(f"{file_info.get('size_bytes')} bytes" if file_info.get("size_bytes") is not None else "-")),
        ("SHA256", f"<code>{html_escape(hashes.get('sha256'))}</code>"),
        ("Highest finding", highest_html),
        ("Machine", html_escape(file_header.get("machine"))),
        ("Subsystem", html_escape(optional.get("subsystem"))),
        ("Compile timestamp", html_escape(file_header.get("timestamp_utc"))),
        ("Entry point", html_escape(ep_text)),
        ("Imports", html_escape(f"{imports.get('dll_count', 0)} DLLs / {imports.get('import_count', 0)} imports")),
        ("Resources", html_escape(f"{resources.get('resource_count', 0)} entries" if resources else "not present")),
        ("Overlay", html_escape(f"{overlay.get('classification')} / {overlay.get('size')} bytes" if overlay else "not present")),
        ("Runtime", html_escape(runtime_text)),
    ]
    card_html = "".join(
        '<div class="metric-card">'
        f'<div class="metric-label">{html_escape(label)}</div>'
        f'<div class="metric-value">{value}</div>'
        '</div>'
        for label, value in cards
    )
    verdict_items = "".join(
        f"<li>{html_escape(item)}</li>"
        for item in summary.get("triage_verdict", {}).get("summary", [])
    )
    inspect_items = "".join(
        f"<li>{html_escape(item)}</li>"
        for item in summary.get("what_to_inspect_first", [])
    )

    return (
        '<div class="metrics-grid">' + card_html + '</div>'
        '<div class="two-col">'
        '<div class="panel"><h3>Triage verdict</h3><ul>' + verdict_items + '</ul></div>'
        '<div class="panel"><h3>What to inspect first</h3><ol>' + inspect_items + '</ol></div>'
        '</div>'
    )


def html_findings(summary, limit=None):
    findings = sorted(summary.get("findings", []), key=finding_sort_key)

    if limit:
        findings = findings[:limit]

    if not findings:
        return '<p class="muted">No structured findings generated.</p>'

    cards = []

    for finding in findings:
        evidence = "".join(
            f"<li><code>{html_escape(preview(item, 240))}</code></li>"
            for item in finding.get("evidence", [])[:10]
        )
        recommendation = ""

        if finding.get("recommendation"):
            recommendation = f'<p class="recommendation"><strong>Next:</strong> {html_escape(finding.get("recommendation"))}</p>'

        context = ""

        if finding.get("context_adjusted"):
            context = (
                '<p class="context-note">Context-adjusted because runtime-heavy context was detected. '
                f'Original: {html_escape(finding.get("original_severity"))}/{html_escape(finding.get("original_confidence"))}.</p>'
            )

        cards.append(
            f'<article class="finding-card severity-border-{html_escape(str(finding.get("severity", "info")).lower())} searchable">'
            '<div class="finding-head">'
            f'<div>{html_severity_badges(finding.get("severity"), finding.get("confidence"))}</div>'
            f'<code>{html_escape(finding.get("id"))}</code>'
            '</div>'
            f'<h3>{html_escape(finding.get("title"))}</h3>'
            + (f'<ul class="evidence-list">{evidence}</ul>' if evidence else '<p class="muted">No evidence listed.</p>')
            + recommendation
            + context
            + '</article>'
        )

    return '<div class="finding-grid">' + "".join(cards) + '</div>'


def html_next_steps(summary):
    steps = summary.get("recommended_next_steps", [])

    if not steps:
        return '<p class="muted">No next steps generated.</p>'

    return '<ol class="steps">' + "".join(f"<li>{html_escape(step)}</li>" for step in steps) + '</ol>'


def html_key_artifacts(summary):
    rows = []

    for artifact in summary.get("key_artifacts", [])[:200]:
        rows.append([
            html_badge(artifact.get("type"), "artifact"),
            f"<code>{html_escape(artifact.get('name'))}</code>",
            f"<code>{html_escape(preview(artifact.get('value'), 240))}</code>",
            html_escape(artifact.get("origin")),
            f"<code>{html_escape(artifact.get('offset'))}</code>",
        ])

    return html_table(["Type", "Name", "Value", "Origin", "Offset"], rows)


def html_runtime(summary):
    runtime = summary.get("runtime_context", {})

    if not runtime.get("detected"):
        return '<p class="muted">No bundled-runtime context detected.</p>'

    parts = [html_kv([
        ("Detected", runtime.get("detected")),
        ("Runtime-heavy", runtime.get("is_runtime_heavy")),
        ("Large runtime shape", runtime.get("large_runtime_shape")),
    ])]
    cards = []

    for family in runtime.get("families", []):
        evidence = "".join(
            f"<li><code>{html_escape(preview(item, 220))}</code></li>"
            for item in family.get("evidence", [])[:12]
        )
        cards.append(
            '<article class="mini-card searchable">'
            f'<h3>{html_escape(family.get("name"))} {html_badge(family.get("confidence"), "confidence")}</h3>'
            f'<ul>{evidence}</ul>'
            '</article>'
        )

    if cards:
        parts.append('<div class="mini-grid">' + "".join(cards) + '</div>')

    if runtime.get("notes"):
        parts.append('<ul>' + "".join(f"<li>{html_escape(note)}</li>" for note in runtime.get("notes", [])) + '</ul>')

    return "".join(parts)


def html_strings(summary):
    strings = summary.get("strings", {})
    stats = strings.get("stats", {})
    parts = [html_kv([
        ("ASCII string count", stats.get("ascii_string_count")),
        ("UTF-16LE string count", stats.get("utf16le_string_count")),
        ("Unique combined string count", stats.get("unique_combined_string_count")),
        ("Longest string length", stats.get("longest_string_length")),
        ("Base64-like total count", stats.get("base64_like_total_count")),
        ("Hex-like total count", stats.get("hex_like_total_count")),
    ])]

    for label, key in [
        ("URLs", "urls"),
        ("IPv4 addresses", "ipv4"),
        ("Domains", "domains"),
        ("Emails", "emails"),
        ("Registry paths", "registry_paths"),
        ("Windows paths", "windows_paths"),
        ("UNC paths", "unc_paths"),
        ("Named pipes", "named_pipes"),
        ("PDB paths", "pdb_paths"),
    ]:
        rows = []

        for item in sorted(strings.get(key, []), key=string_item_sort_key)[:160]:
            context = item.get("context") or item.get("ip_type") or item.get("url_type") or item.get("noise_reason") or item.get("parse_reason")
            rows.append([
                f"<code>{html_escape(preview(item.get('value'), 260))}</code>",
                html_badge(item.get("confidence"), "confidence"),
                f"<code>{html_escape(item.get('offset'))}</code>",
                html_escape(item.get("origin")),
                html_escape(item.get("encoding")),
                html_escape(context),
            ])

        parts.append(html_section(
            label,
            html_table(["Value", "Confidence", "Offset", "Origin", "Encoding", "Context"], rows),
            open_by_default=key in {"urls", "ipv4", "domains"},
            section_id=f"strings-{key}"
        ))

    if strings.get("keyword_hits"):
        cards = []

        for category, values in strings.get("keyword_hits", {}).items():
            items = "".join(
                f"<li><code>{html_escape(preview(item.get('value'), 220))}</code> "
                f"<span class='muted'>{html_escape(item.get('offset'))} / {html_escape(item.get('origin'))}</span></li>"
                for item in values[:100]
            ) or '<li class="muted">None</li>'
            cards.append(
                '<article class="mini-card searchable">'
                f'<h3>{html_escape(category)}</h3><ul>{items}</ul>'
                '</article>'
            )

        parts.append(html_section("Keyword hits", '<div class="mini-grid">' + "".join(cards) + '</div>', open_by_default=False))

    return "".join(parts)


def html_encoded_blobs(summary):
    blobs = sorted(summary.get("strings", {}).get("encoded_blobs", []), key=encoded_blob_sort_key)

    if not blobs:
        return '<p class="muted">No decodable base64/hex blob candidates with useful decoded content found.</p>'

    cards = []

    for blob in blobs[:100]:
        assessment = blob.get("assessment", {}) or {}
        reasons = "; ".join(assessment.get("reasons", [])[:6])
        sample_strings = "".join(
            f"<li><code>{html_escape(preview(item, 220))}</code></li>"
            for item in blob.get("sample_strings", [])[:8]
        )
        indicators = []

        for label, key in [("URLs", "urls"), ("Domains", "domains"), ("IPv4", "ipv4")]:
            if blob.get(key):
                values = ", ".join(str(item) for item in blob.get(key, [])[:12])
                indicators.append(f"<p><strong>{html_escape(label)}:</strong> <code>{html_escape(values)}</code></p>")

        cards.append(
            '<article class="mini-card searchable">'
            '<div class="finding-head">'
            f'{html_badge(blob.get("type"), "artifact")} {html_badge(assessment.get("confidence"), "confidence")}'
            f'<code>{html_escape(blob.get("source_offset"))}</code>'
            '</div>'
            f'<h3>{html_escape(assessment.get("content_type") or "decoded blob")}</h3>'
            + html_kv([
                ("Source origin", blob.get("source_origin")),
                ("Decoded size", blob.get("decoded_size")),
                ("Decoded entropy", blob.get("decoded_entropy")),
                ("Magic", blob.get("magic_hint")),
                ("Decoded SHA256", blob.get("decoded_sha256")),
                ("Interesting", assessment.get("interesting")),
                ("Triage interesting", assessment.get("triage_interesting")),
                ("Suspicious", assessment.get("suspicious")),
                ("Reason", reasons),
            ])
            + "".join(indicators)
            + (f'<h4>Sample decoded strings</h4><ul>{sample_strings}</ul>' if sample_strings else "")
            + '</article>'
        )

    return '<div class="mini-grid">' + "".join(cards) + '</div>'


def html_imports(summary):
    imports = summary.get("imports", {})
    parts = [html_kv([
        ("Import table present", imports.get("import_table_present")),
        ("DLL count", imports.get("dll_count")),
        ("Import count", imports.get("import_count")),
        ("Ordinal-only import count", imports.get("ordinal_only_import_count")),
    ])]

    if imports.get("api_combination_findings"):
        parts.append('<h3>API combination findings</h3>')
        parts.append(html_findings({"findings": imports.get("api_combination_findings", [])}))

    if imports.get("capability_imports"):
        cards = []

        for category, values in imports.get("capability_imports", {}).items():
            items = "".join(f"<li><code>{html_escape(value)}</code></li>" for value in values[:80])
            cards.append(
                '<article class="mini-card searchable">'
                f'<h3>{html_escape(category)}</h3><ul>{items}</ul>'
                '</article>'
            )

        parts.append('<h3>Capability imports</h3><div class="mini-grid">' + "".join(cards) + '</div>')

    if imports.get("dlls"):
        dlls = " ".join(html_badge(dll, "dll") for dll in imports.get("dlls", []))
        parts.append('<h3>Imported DLLs</h3><p class="wrap-list">' + dlls + '</p>')

    return "".join(parts)


def html_sections_table(summary):
    rows = []

    for section in summary.get("sections", []):
        rows.append([
            f"<code>{html_escape(section.get('name'))}</code>",
            f"<code>{html_escape(section.get('virtual_address'))}</code>",
            html_escape(section.get("virtual_size")),
            f"<code>{html_escape(section.get('raw_pointer'))}</code>",
            html_escape(section.get("raw_size")),
            html_escape(section.get("entropy")),
            html_flags(section.get("flags", [])),
            f"<code>{html_escape(section.get('sha256'))}</code>",
        ])

    content = html_table(["Name", "VA", "Virtual size", "Raw ptr", "Raw size", "Entropy", "Flags", "SHA256"], rows)
    anomalies = summary.get("section_layout_anomalies", [])

    if anomalies:
        anomaly_rows = []

        for anomaly in anomalies:
            anomaly_rows.append([
                html_badge(anomaly.get("type"), "flag"),
                html_escape(anomaly.get("section") or ", ".join(anomaly.get("sections", []))),
                f"<code>{html_escape(anomaly.get('range') or anomaly.get('range_a'))}</code>",
                f"<code>{html_escape(anomaly.get('range_b'))}</code>",
            ])

        content += '<h3>Section layout anomalies</h3>'
        content += html_table(["Type", "Section(s)", "Range A", "Range B"], anomaly_rows)

    return content


def html_resources(summary):
    resources = summary.get("resources")

    if not resources:
        return '<p class="muted">No resources found.</p>'

    by_type_rows = []

    for resource_type, info in sorted(resources.get("by_type", {}).items()):
        by_type_rows.append([
            html_badge(resource_type, "resource"),
            html_escape(info.get("count")),
            html_escape(info.get("max_size")),
            html_escape(info.get("max_entropy")),
            html_badge(info.get("highest_priority"), "priority"),
        ])

    content = '<h3>Resource type summary</h3>'
    content += html_table(["Type", "Count", "Max size", "Max entropy", "Highest priority"], by_type_rows)

    interesting_rows = []

    for item in resources.get("interesting_resources", [])[:100]:
        embedded = ", ".join(
            f"{hit.get('magic')}@{hit.get('offset')}({hit.get('confidence')})"
            for hit in item.get("embedded_magic_hits_compact", [])[:5]
        )
        reasons = "; ".join(item.get("priority_reasons", [])[:4])
        interesting_rows.append([
            f"<code>{html_escape(item.get('resource_path'))}</code>",
            html_badge(item.get("priority"), "priority"),
            html_escape(item.get("size")),
            html_escape(item.get("entropy")),
            html_escape(item.get("magic_hint")),
            f"<code>{html_escape(item.get('file_offset'))}</code>",
            html_escape(embedded),
            html_escape(reasons),
        ])

    if interesting_rows:
        content += '<h3>Interesting resources</h3>'
        content += html_table(["Path", "Priority", "Size", "Entropy", "Magic", "Offset", "Embedded magic", "Reason"], interesting_rows)

    return content


def html_overlay_tls_certificate(summary):
    overlay = summary.get("overlay")
    tls = summary.get("tls")
    certificate = summary.get("certificate") or {}
    dotnet = summary.get("dotnet") or {}
    parts = []

    if overlay:
        magic = ", ".join(
            f"{hit.get('magic')}@{hit.get('offset')}({hit.get('confidence')})"
            for hit in overlay.get("embedded_magic_hits", [])[:10]
        )
        parts.append('<h3>Overlay</h3>')
        parts.append(html_kv([
            ("Offset", overlay.get("offset")),
            ("Size", overlay.get("size")),
            ("Entropy", overlay.get("entropy")),
            ("Magic hint", overlay.get("magic_hint")),
            ("Classification", overlay.get("classification")),
            ("SHA256", overlay.get("sha256")),
            ("Embedded magic", magic),
        ]))
    else:
        parts.append('<h3>Overlay</h3><p class="muted">No overlay found.</p>')

    parts.append('<h3>Certificate</h3>')
    parts.append(html_kv([
        ("Present", certificate.get("present")),
        ("File offset", certificate.get("file_offset")),
        ("Size", certificate.get("size")),
        ("Note", certificate.get("note")),
    ]))

    if tls:
        callbacks = ", ".join(
            f"{item.get('va')} / {item.get('section')}"
            for item in tls.get("callbacks", [])
        )
        parts.append('<h3>TLS</h3>')
        parts.append(html_kv([
            ("Address of callbacks", tls.get("address_of_callbacks")),
            ("Callback count", tls.get("callback_count")),
            ("Callbacks", callbacks),
            ("Characteristics", tls.get("characteristics")),
        ]))
    else:
        parts.append('<h3>TLS</h3><p class="muted">No TLS directory found.</p>')

    parts.append('<h3>.NET</h3>')
    parts.append(html_kv([
        ("Is .NET", dotnet.get("is_dotnet")),
        ("CLR header RVA", dotnet.get("clr_header_rva")),
        ("CLR header size", dotnet.get("clr_header_size")),
    ]))

    return "".join(parts)


def html_metadata(summary):
    file_info = summary.get("file", {})
    hashes = summary.get("hashes", {})
    dos = summary.get("dos_header", {})
    file_header = summary.get("file_header", {})
    optional = summary.get("optional_header", {})
    version_info = summary.get("version_info", {})
    rich = summary.get("rich_header")
    debug = summary.get("debug", [])
    directories = summary.get("data_directories", [])
    delay_imports = summary.get("delay_imports")
    exports = summary.get("exports")
    parts = []

    parts.append('<h3>File identity</h3>')
    parts.append(html_kv([
        ("File", file_info.get("name")),
        ("Path", file_info.get("path")),
        ("Size", file_info.get("size_bytes")),
        ("MD5", hashes.get("md5")),
        ("SHA1", hashes.get("sha1")),
        ("SHA256", hashes.get("sha256")),
        ("Imphash", hashes.get("imphash")),
        ("Authentihash SHA256", hashes.get("authentihash_sha256")),
    ]))

    parts.append('<h3>Headers</h3>')
    parts.append(html_kv([
        ("DOS e_magic", dos.get("e_magic")),
        ("DOS e_lfanew", dos.get("e_lfanew")),
        ("Machine", f"{file_header.get('machine')} ({file_header.get('machine_raw')})"),
        ("Sections", file_header.get("number_of_sections")),
        ("Compile timestamp UTC", file_header.get("timestamp_utc")),
        ("Compile timestamp raw", file_header.get("timestamp_raw")),
        ("Timestamp notes", file_header.get("timestamp_notes")),
        ("Characteristics", file_header.get("characteristics")),
        ("PE magic", optional.get("magic")),
        ("Linker version", optional.get("linker_version")),
        ("Subsystem", optional.get("subsystem")),
        ("Image base", optional.get("image_base")),
        ("Size of image", optional.get("size_of_image")),
        ("Size of headers", optional.get("size_of_headers")),
        ("Section alignment", optional.get("section_alignment")),
        ("File alignment", optional.get("file_alignment")),
        ("DLL characteristics", optional.get("dll_characteristics")),
    ]))

    if version_info:
        parts.append('<h3>Version info</h3>')
        parts.append(html_kv(sorted(version_info.items())))

    if rich:
        parts.append('<h3>Rich header</h3>')
        parts.append(html_kv(sorted(rich.items())))

    if debug:
        rows = []

        for item in debug:
            rows.append([
                html_escape(item.get("type")),
                html_escape(item.get("timestamp_utc")),
                html_escape(item.get("size_of_data")),
                f"<code>{html_escape(item.get('pdb_path'))}</code>",
            ])

        parts.append('<h3>Debug / PDB</h3>')
        parts.append(html_table(["Type", "Timestamp UTC", "Size", "PDB path"], rows))

    if directories:
        rows = []

        for directory in directories:
            rows.append([
                html_escape(directory.get("name")),
                f"<code>{html_escape(directory.get('rva'))}</code>",
                html_escape(directory.get("size")),
            ])

        parts.append('<h3>Data directories</h3>')
        parts.append(html_table(["Name", "RVA", "Size"], rows))

    if delay_imports:
        parts.append('<h3>Delay imports</h3>')
        parts.append(html_kv([
            ("DLL count", delay_imports.get("dll_count")),
            ("DLLs", delay_imports.get("dlls")),
            ("Sample imports", delay_imports.get("sample_imports")),
        ]))

    if exports:
        parts.append('<h3>Exports</h3>')
        parts.append(html_kv([
            ("DLL name", exports.get("dll_name")),
            ("Export count", exports.get("export_count")),
            ("Named export count", exports.get("named_export_count")),
            ("Ordinal-only export count", exports.get("ordinal_only_export_count")),
            ("Sample exports", exports.get("sample_exports")),
        ]))

    if summary.get("parser_warnings"):
        parts.append('<h3>Parser warnings</h3>')
        parts.append('<ul>' + "".join(f"<li>{html_escape(warning)}</li>" for warning in summary.get("parser_warnings", [])) + '</ul>')

    return "".join(parts)


def format_html(summary, text_content=None):
    file_name = summary.get("file", {}).get("name", "PE report")
    title = f"PE triage report - {file_name}"
    generated_utc = datetime.now(timezone.utc).isoformat()
    json_text = json.dumps(summary, indent=2)
    section_specs = [
        ("Overview", html_overview(summary), True, None, None),
        ("Metadata and headers", html_metadata(summary), True, None, None),
        ("Top findings", html_findings(summary, limit=5), True, None, 5),
        ("All findings", html_findings(summary), True, None, None),
        ("Recommended next steps", html_next_steps(summary), True, None, None),
        ("Key artifacts", html_key_artifacts(summary), True, None, None),
        ("Runtime context", html_runtime(summary), True, None, None),
        ("Imports", html_imports(summary), True, None, None),
        ("Sections", html_sections_table(summary), True, None, None),
        ("Resources", html_resources(summary), True, None, None),
        ("Overlay / TLS / certificate / .NET", html_overlay_tls_certificate(summary), True, None, None),
        ("Interesting strings", html_strings(summary), False, None, None),
        ("Decoded blobs", html_encoded_blobs(summary), False, None, None),
        ("Raw text report", f'<pre>{html_escape(text_content or "")}</pre>', False, None, None),
        ("Raw JSON", f'<pre>{html_escape(json_text)}</pre>', False, None, None),
    ]
    nav_titles = [title for title, _content, _open, _section_id, _limit in section_specs]
    sections = [
        html_section(
            title,
            content,
            open_by_default=open_by_default,
            section_id=section_id,
            meta=html_section_meta(summary, title, visible_limit=limit),
        )
        for title, content, open_by_default, section_id, limit in section_specs
    ]
    css = "".join([
        ":root{--bg:#0f172a;--panel:#111827;--panel2:#1f2937;--text:#e5e7eb;--muted:#9ca3af;--border:#374151;--code:#020617;--high:#ef4444;--medium:#f59e0b;--low:#3b82f6;--accent:#38bdf8}",
        "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;line-height:1.45}",
        "a{color:var(--accent);text-decoration:none}code,pre{font-family:Consolas,'Cascadia Mono','Liberation Mono',Menlo,monospace}",
        "pre{white-space:pre-wrap;word-break:break-word;background:var(--code);border:1px solid var(--border);border-radius:12px;padding:1rem;overflow:auto}",
        "code{background:rgba(2,6,23,.8);border:1px solid rgba(55,65,81,.7);border-radius:6px;padding:.1rem .3rem;word-break:break-word}",
        ".layout{display:grid;grid-template-columns:260px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;overflow:auto;background:#020617;border-right:1px solid var(--border);padding:1.25rem}",
        ".sidebar h1{font-size:1rem;margin:0 0 .35rem}.subtitle{color:var(--muted);font-size:.82rem;margin-bottom:1rem;word-break:break-word}.sidebar nav{display:grid;gap:.35rem}.sidebar a{display:block;color:var(--text);padding:.45rem .6rem;border-radius:8px}.sidebar a:hover{background:var(--panel2)}",
        ".main{min-width:0;padding:1.5rem 2rem 4rem}.hero{background:linear-gradient(135deg,rgba(56,189,248,.14),rgba(239,68,68,.10));border:1px solid var(--border);border-radius:18px;padding:1.25rem;margin-bottom:1rem}.hero h2{margin:0 0 .4rem;font-size:1.6rem}.hero p{margin:0;color:var(--muted)}",
        ".search-box{width:100%;border:1px solid var(--border);background:var(--panel);color:var(--text);border-radius:10px;padding:.75rem .85rem;margin:1rem 0;font-size:.95rem}",
        "details.section{background:var(--panel);border:1px solid var(--border);border-radius:14px;margin:0 0 1rem;overflow:hidden}details.section>summary{cursor:pointer;font-weight:700;font-size:1.05rem;padding:.95rem 1.1rem;background:rgba(31,41,55,.8);display:flex;align-items:center;justify-content:space-between;gap:.9rem}.summary-title{min-width:0}.summary-meta{display:flex;align-items:center;justify-content:flex-end;gap:.25rem;flex-wrap:wrap}.section-body{padding:1rem}",
        ".metrics-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:.8rem}.metric-card,.panel,.finding-card,.mini-card{background:rgba(31,41,55,.72);border:1px solid var(--border);border-radius:12px;padding:.85rem}.metric-label{color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;margin-bottom:.25rem}.metric-value{font-weight:650;word-break:break-word}",
        ".two-col{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:.8rem;margin-top:.8rem}.finding-grid,.mini-grid{display:grid;gap:.85rem}.finding-card h3,.mini-card h3,.panel h3{margin:.55rem 0}.finding-head{display:flex;justify-content:space-between;gap:.6rem;align-items:center;flex-wrap:wrap}",
        ".severity-border-high{border-left:5px solid var(--high)}.severity-border-medium{border-left:5px solid var(--medium)}.severity-border-low{border-left:5px solid var(--low)}.severity-border-info{border-left:5px solid var(--muted)}",
        ".badge{display:inline-block;border-radius:999px;padding:.15rem .5rem;font-size:.76rem;font-weight:700;border:1px solid rgba(255,255,255,.14);margin:.08rem .1rem .08rem 0;white-space:nowrap}.status-badge{display:inline-block;border-radius:999px;padding:.16rem .48rem;font-size:.72rem;font-weight:700;border:1px solid rgba(255,255,255,.12);white-space:nowrap;background:rgba(148,163,184,.12);color:#cbd5e1}.status-empty{color:var(--muted);background:rgba(148,163,184,.08)}.status-content{color:#bae6fd;background:rgba(56,189,248,.12);border-color:rgba(56,189,248,.28)}.status-warning,.status-medium{color:#fde68a;background:rgba(245,158,11,.14);border-color:rgba(245,158,11,.35)}.status-high{color:#fecaca;background:rgba(239,68,68,.16);border-color:rgba(239,68,68,.42)}.status-low{color:#bfdbfe;background:rgba(59,130,246,.14);border-color:rgba(59,130,246,.34)}.status-info{color:#ddd6fe;background:rgba(139,92,246,.14);border-color:rgba(139,92,246,.34)}.muted{color:var(--muted)}",
        ".severity-high,.priority-high{background:rgba(239,68,68,.18);color:#fecaca;border-color:rgba(239,68,68,.5)}.severity-medium,.priority-medium{background:rgba(245,158,11,.18);color:#fde68a;border-color:rgba(245,158,11,.5)}.severity-low,.priority-low{background:rgba(59,130,246,.18);color:#bfdbfe;border-color:rgba(59,130,246,.5)}.severity-info,.priority-info{color:var(--muted)}",
        ".confidence-high{background:rgba(34,197,94,.16);color:#bbf7d0}.confidence-medium{background:rgba(245,158,11,.16);color:#fde68a}.confidence-low{background:rgba(156,163,175,.16);color:#e5e7eb}.flag-execute-write,.flag-resource-executable,.flag-text-writable,.flag-raw-outside-file{background:rgba(239,68,68,.18);color:#fecaca}.flag-high-entropy,.flag-suspicious-name,.flag-unusual-name,.flag-virtual-only,.flag-large-virtual-size{background:rgba(245,158,11,.18);color:#fde68a}",
        ".table-wrap{width:100%;overflow-x:auto}table{width:100%;border-collapse:collapse;margin:.5rem 0 1rem}th,td{border-bottom:1px solid var(--border);padding:.55rem;text-align:left;vertical-align:top}th{color:#cbd5e1;background:rgba(2,6,23,.45)}table.kv th{width:230px;color:var(--muted)}.evidence-list,.steps,.mini-card ul{padding-left:1.25rem}.recommendation{color:#bbf7d0}.context-note{color:#fde68a}.wrap-list{line-height:1.85}.hidden-by-search{display:none!important}",
        "@media(max-width:900px){.layout{grid-template-columns:1fr}.sidebar{position:static;height:auto}.main{padding:1rem}details.section>summary{align-items:flex-start;flex-direction:column}.summary-meta{justify-content:flex-start}}",
    ])
    js = "".join([
        "const s=document.getElementById('globalSearch');",
        "s?.addEventListener('input',()=>{const q=s.value.trim().toLowerCase();",
        "document.querySelectorAll('.searchable,.searchable-table tbody tr').forEach(e=>{",
        "if(!q){e.classList.remove('hidden-by-search');return}",
        "e.classList.toggle('hidden-by-search',!e.innerText.toLowerCase().includes(q));});});",
    ])

    return (
        '<!doctype html><html lang="en"><head>'
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>{html_escape(title)}</title><style>{css}</style></head><body>'
        '<div class="layout"><aside class="sidebar">'
        '<h1>PE triage report</h1>'
        f'<div class="subtitle">{html_escape(file_name)}<br>Generated UTC: {html_escape(generated_utc)}</div>'
        '<nav>' + "".join(html_nav(title) for title in nav_titles) + '</nav>'
        '</aside><main class="main"><section class="hero">'
        f'<h2>{html_escape(title)}</h2>'
        '<p>Static HTML report generated from the structured summary data. Malware strings are rendered as text/code, not as clickable links.</p>'
        '</section><input id="globalSearch" class="search-box" type="search" placeholder="Filter visible findings, tables, imports, strings, and resources...">'
        + "".join(sections) + f'<script>{js}</script></main></div></body></html>'
    )

ANSI_COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red_bold": "\033[1;31m",
    "yellow_bold": "\033[1;33m",
    "green_bold": "\033[1;32m",
    "blue_bold": "\033[1;34m",
    "cyan_bold": "\033[1;36m",
    "magenta_bold": "\033[1;35m",
}


def color_enabled():
    if os.environ.get("NO_COLOR"):
        return False

    if os.environ.get("FORCE_COLOR"):
        return True

    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def color_text(value, color_name, enabled=True):
    if not enabled:
        return value

    color = ANSI_COLORS.get(color_name)

    if not color:
        return value

    return f"{color}{value}{ANSI_COLORS['reset']}"


def colorize_report_line(line, enabled=True):
    if not enabled:
        return line

    stripped = line.strip()

    if not stripped:
        return line

    if set(stripped) in [{"="}, {"-"}] and len(stripped) >= 20:
        return color_text(line, "dim", enabled)

    if stripped.isupper() and len(stripped) <= 80:
        return color_text(line, "cyan_bold", enabled)

    def severity_replacer(match):
        severity = match.group(1)
        confidence = match.group(2)

        severity_color = {
            "HIGH": "red_bold",
            "MEDIUM": "yellow_bold",
            "LOW": "blue_bold",
            "INFO": "dim",
        }.get(severity, "bold")

        confidence_color = {
            "high": "green_bold",
            "medium": "yellow_bold",
            "low": "dim",
        }.get(confidence, "bold")

        return (
            "["
            + color_text(severity, severity_color, enabled)
            + " / "
            + color_text(confidence, confidence_color, enabled)
            + "]"
        )

    line = re.sub(
        r"\[(HIGH|MEDIUM|LOW|INFO) / (high|medium|low)\]",
        severity_replacer,
        line
    )

    flag_colors = {
        "EXECUTE_WRITE": "red_bold",
        "HIGH_ENTROPY": "yellow_bold",
        "SUSPICIOUS_NAME": "yellow_bold",
        "UNUSUAL_NAME": "yellow_bold",
        "RESOURCE_EXECUTABLE": "red_bold",
        "TEXT_WRITABLE": "red_bold",
        "RAW_OUTSIDE_FILE": "red_bold",
        "VIRTUAL_ONLY": "yellow_bold",
        "LARGE_VIRTUAL_SIZE": "yellow_bold",
    }

    for flag, color_name in flag_colors.items():
        line = re.sub(
            rf"(?<![A-Z0-9_]){re.escape(flag)}(?![A-Z0-9_])",
            color_text(flag, color_name, enabled),
            line
        )

    for prefix, color_name in {
        "Evidence:": "dim",
        "Next:": "green_bold",
        "Verdict note:": "magenta_bold",
    }.items():
        if stripped.startswith(prefix):
            indent_length = len(line) - len(line.lstrip())
            indent = line[:indent_length]
            rest = line[indent_length + len(prefix):]
            return indent + color_text(prefix, color_name, enabled) + rest

    return line


def colorize_report(content, enabled=True):
    return "\n".join(
        colorize_report_line(line, enabled)
        for line in content.splitlines()
    )

def print_text_report(content, use_color=True):
    if use_color:
        content = colorize_report(content, enabled=color_enabled())

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
    parser.add_argument("--no-html", action="store_true", help="do not write HTML report")
    parser.add_argument("--html-output", metavar="PATH", help="HTML report path (default: <sample>_pe_report.html)")
    parser.add_argument("-p", "--print", dest="print_text", action="store_true", help="print text report to console")
    parser.add_argument("--no-color", action="store_true", help="disable colored console output")
    parser.add_argument("--no-progress", action="store_true", help="disable delayed progress indicator")
    args = parser.parse_args()

    if args.json_output and not args.json:
        args.json = True

    text_output_path = args.output or default_text_output_path(args.path)
    json_output_path = args.json_output or default_json_output_path(args.path)
    html_output_path = args.html_output or default_html_output_path(args.path)

    progress_total = 5
    if args.no_html:
        progress_total -= 1
    if args.json:
        progress_total += 1

    progress = DelayedProgress(
        total=progress_total,
        label=f"Analyzing {os.path.basename(args.path)}",
        delay=1.5,
        enabled=not args.no_progress
    )
    progress.start()

    try:
        progress.update("Building PE summary...")

        try:
            summary = summarize(args.path)
        except pefile.PEFormatError as e:
            print(f"Not a valid PE file: {e}", file=sys.stderr)
            sys.exit(1)
        except FileNotFoundError:
            print("File not found", file=sys.stderr)
            sys.exit(1)

        progress.update("Formatting text report...")
        text_content = format_text(summary)

        html_content = None

        if not args.no_html:
            progress.update("Formatting HTML report...")
            html_content = format_html(summary, text_content=text_content)

        progress.update("Writing text report...")

        with open(text_output_path, "w", encoding="utf-8") as f:
            f.write(text_content)

        if not args.no_html:
            progress.update("Writing HTML report...")

            with open(html_output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

        if args.json:
            progress.update("Writing JSON report...")
            json_content = json.dumps(summary, indent=2)

            with open(json_output_path, "w", encoding="utf-8") as f:
                f.write(json_content)

    finally:
        progress.done()

    if args.print_text:
        print_text_report(text_content, use_color=not args.no_color)

    print(f"Wrote text report to: {text_output_path}", file=sys.stderr)

    if not args.no_html:
        print(f"Wrote HTML report to: {html_output_path}", file=sys.stderr)

    if args.json:
        print(f"Wrote detailed JSON report to: {json_output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
