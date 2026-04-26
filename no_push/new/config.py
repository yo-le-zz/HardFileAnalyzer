# ============================================================
#  HARD FILE ANALYZER — config.py
#  Constantes globales, thème, modules, patterns, scoring
# ============================================================

APP_VERSION = "4.0-hybrid"
APP_TITLE   = "HARD FILE ANALYZER"

# ─── Catppuccin Macchiato ───────────────────────────────────
C = {
    "base":      "#24273a",
    "mantle":    "#1e2030",
    "crust":     "#181926",
    "surface0":  "#363a4f",
    "surface1":  "#494d64",
    "surface2":  "#5b6078",
    "overlay0":  "#6e738d",
    "overlay1":  "#8087a2",
    "text":      "#cad3f5",
    "subtext0":  "#a5adcb",
    "subtext1":  "#b8c0e0",
    "lavender":  "#b7bdf8",
    "blue":      "#8aadf4",
    "sapphire":  "#7dc4e4",
    "sky":       "#91d7e3",
    "teal":      "#8bd5ca",
    "green":     "#a6da95",
    "yellow":    "#eed49f",
    "peach":     "#f5a97f",
    "maroon":    "#ee99a0",
    "red":       "#ed8796",
    "mauve":     "#c6a0f6",
    "pink":      "#f5bde6",
    "flamingo":  "#f0c6c6",
    "rosewater": "#f4dbd6",
}

# ─── Risk levels ────────────────────────────────────────────
RISK_LEVELS = [
    (0,  20,  "SAFE",      C["green"],   "✅"),
    (21, 50,  "LOW RISK",  C["yellow"],  "⚠️"),
    (51, 75,  "SUSPECT",   C["peach"],   "🔶"),
    (76, 90,  "HIGH RISK", C["maroon"],  "🚨"),
    (91, 100, "DANGEROUS", C["red"],     "☠️"),
]

def get_risk(score: int):
    for lo, hi, label, color, icon in RISK_LEVELS:
        if lo <= score <= hi:
            return label, color, icon
    return "UNKNOWN", C["overlay0"], "❓"

# ─── Module definitions ──────────────────────────────────────
MODULES = {
    "static":    {"name": "Statique",     "desc": "Hash · Entropie C++ · Structure · Strings · PE",    "icon": "🔬", "tpm": 0.3,  "default": True},
    "heuristic": {"name": "Heuristique",  "desc": "Obfuscation · Ransomware · Injection · Anti-debug", "icon": "🧠", "tpm": 0.6,  "default": True},
    "network":   {"name": "Réseau",       "desc": "URLs · IPs encodées · Domaines suspects · C2",      "icon": "🌐", "tpm": 0.2,  "default": True},
    "system":    {"name": "Système",      "desc": "Fichiers sensibles · Registre · Élévation · Boot",  "icon": "⚙️", "tpm": 0.3,  "default": True},
    "iq":        {"name": "IQ Deep",      "desc": "PE parsing · RTLO · Homoglyphes · Coherence totale","icon": "🧩", "tpm": 0.5,  "default": True},
    "cloud":     {"name": "Cloud (VT)",   "desc": "VirusTotal hash · Upload · Score multi-AV",         "icon": "☁️", "tpm": 4.0,  "default": False},
    "sandbox":   {"name": "Sandbox Réelle","desc":"Exécution isolée psutil · Fichiers · Réseau · Procs","icon": "📦", "tpm": 15.0, "default": False},
}

# ─── Module reliability weights (for non-linear scoring) ────
MODULE_RELIABILITY = {
    "cloud":     1.00,  # VirusTotal = ground truth
    "sandbox":   0.92,  # Behavioral = très fiable
    "heuristic": 0.85,
    "system":    0.72,
    "static":    0.65,
    "iq":        0.55,
    "network":   0.48,
}

# ─── Severity levels for individual findings ────────────────
SEV = {
    "CRITICAL": 0.95,
    "HIGH":     0.75,
    "MEDIUM":   0.50,
    "LOW":      0.25,
    "INFO":     0.10,
}

# ─── Magic bytes → file type ─────────────────────────────────
MAGIC_SIGS = {
    b'\x4d\x5a':         "PE Executable",
    b'\x7f\x45\x4c\x46': "ELF Binary",
    b'\x25\x50\x44\x46': "PDF",
    b'\x50\x4b\x03\x04': "ZIP Archive",
    b'\x52\x61\x72\x21': "RAR Archive",
    b'\x1f\x8b':         "GZip",
    b'\x42\x5a\x68':     "BZip2",
    b'\xd0\xcf\x11\xe0': "OLE2 (MS Office legacy)",
    b'\x89\x50\x4e\x47': "PNG",
    b'\xff\xd8\xff':     "JPEG",
    b'\x47\x49\x46\x38': "GIF",
    b'\x23\x21':         "Script (shebang)",
    b'\xca\xfe\xba\xbe': "Mach-O Binary",
    b'\x7b\x5c\x72\x74': "RTF",
    b'\xd4\xc3\xb2\xa1': "PCAP",
    b'\x4f\x67\x67\x53': "OGG",
    b'\x00\x00\x01\xba': "MPEG Stream",
    b'\x49\x44\x33':     "MP3",
    b'\x66\x4c\x61\x43': "FLAC",
    b'\x38\x42\x50\x53': "PSD",
    b'\x1a\x45\xdf\xa3': "MKV/EBML",
    b'\x00\x00\x00\x0c': "MP4/MOV",
    b'\x37\x7a\xbc\xaf': "7-Zip",
    b'\xfd\x37\x7a\x58': "XZ",
}

PACKER_SIGS = [
    b'UPX0', b'UPX1', b'UPX2', b'MPRESS', b'.aspack', b'.aPLib',
    b'PEC2TO', b'FSG!', b'PEPACK', b'Themida', b'WinLicence',
    b'Enigma', b'VMProtect', b'Obsidium', b'ACProtect', b'EXEcryptor',
    b'nSPACK', b'SVKP', b'tElock', b'yoda\'s', b'Morphine',
]

EXT_EXPECTED = {
    '.exe': ["PE Executable"], '.dll': ["PE Executable"], '.sys': ["PE Executable"],
    '.drv': ["PE Executable"], '.ocx': ["PE Executable"], '.cpl': ["PE Executable"],
    '.pdf': ["PDF"], '.jpg': ["JPEG"], '.jpeg': ["JPEG"], '.png': ["PNG"],
    '.gif': ["GIF"], '.zip': ["ZIP"], '.rar': ["RAR"], '.gz': ["GZip"],
    '.bz2': ["BZip2"], '.7z': ["7-Zip"], '.xz': ["XZ"],
    '.docx': ["ZIP"], '.xlsx': ["ZIP"], '.pptx': ["ZIP"], '.odt': ["ZIP"],
    '.mp3': ["MP3"], '.ogg': ["OGG"], '.flac': ["FLAC"],
    '.psd': ["PSD"], '.pcap': ["PCAP"],
    '.rtf': ["RTF"], '.bat': ["text", "Script"], '.cmd': ["text", "Script"],
    '.ps1': ["text", "Script"], '.vbs': ["text", "Script"],
    '.py':  ["text", "Script"], '.js':  ["text", "Script"],
    '.mkv': ["MKV"], '.mp4': ["MP4"],
}

# ─── RTLO / Unicode attack characters ───────────────────────
RTLO_CHARS  = ['\u202e', '\u200f', '\u200e', '\u202b', '\u202a']
ZERO_WIDTH  = ['\u200b', '\u200c', '\u200d', '\ufeff']

# ─── Homoglyph sets (latin ↔ cyrillic / greek) ──────────────
HOMOGLYPHS = {
    'a': ['а','α'], 'e': ['е','ε'], 'o': ['о','ο'], 'p': ['р','ρ'],
    'c': ['с','ϲ'], 'x': ['х','χ'], 'y': ['у','γ'], 'i': ['і','ι'],
    'j': ['ј'], 'g': ['ɡ'], 'B': ['В'], 'H': ['Н'], 'K': ['К'],
    'M': ['М'], 'T': ['Т'], 'A': ['А'], 'E': ['Е'], 'O': ['О'],
}

# ─── Deep heuristic patterns ─────────────────────────────────
RANSOMWARE_BYTES = [
    b"encrypt", b"ransom", b"bitcoin", b"YOUR FILES", b"your files",
    b".locked", b".encrypted", b"DECRYPT_INSTRUCTION", b"HELP_DECRYPT",
    b"shadow", b"vssadmin", b"bcdedit", b"wbadmin", b"AES-256", b"RSA-2048",
    b"CryptEncrypt", b"CryptGenKey", b"CryptImportKey", b"CreateEncryptor",
    b"wallet", b"tor2web", b"onion", b"RANSOM", b"decrypt_files",
    b"EncryptFile", b"ReadFile", b"WriteFile", b"FindFirstFile",
]

CODE_INJECTION_APIS = [
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread", "SetWindowsHookEx",
    "QueueUserAPC", "NtQueueApcThread", "MapViewOfFile2",
    "NtMapViewOfSection", "NtAllocateVirtualMemory", "SuspendThread",
    "ResumeThread", "GetThreadContext", "SetThreadContext",
    "Process32First", "Process32Next", "OpenProcess",
]

ANTI_DEBUG_APIS = [
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugString",
    "GetTickCount", "QueryPerformanceCounter",
    "NtSetInformationThread", "CloseHandle",
    "UnhandledExceptionFilter", "NtGlobalFlag",
    "FindWindow", "GetForegroundWindow",
]

ANTI_VM_STRINGS = [
    "VBOX", "VMWARE", "VirtualBox", "vboxservice", "vmtoolsd",
    "wine_get_unix_file_name", "QEMU", "BOCHS", "Hyper-V",
    "vmci", "vmhgfs", "vmx_svga", "vmmouse", "Sandboxie",
    "SbieDll", "dbghelp", "api_log", "dir_watch", "pstorec",
    "vmware.exe", "vboxservice.exe", "vboxtray.exe",
    "VIRTUAL_MACHINE", "SANDBOX", "CWSandbox",
]

PERSISTENCE_PATTERNS = [
    "CurrentVersion\\Run", "CurrentVersion\\RunOnce",
    "Winlogon\\Shell", "Winlogon\\Userinit",
    "SYSTEM\\CurrentControlSet\\Services",
    "\\Startup\\", "schtasks", "SCHTASKS", "at.exe",
    "SC CREATE", "sc create", "bcdedit", "BootExecute",
    "AppInit_DLLs", "Image File Execution Options",
    "IFEO", "Debugger",
]

PRIVESC_PATTERNS = [
    "SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege",
    "AdjustTokenPrivileges", "ImpersonateLoggedOnUser",
    "CreateProcessWithTokenW", "TokenImpersonation",
    "runas", "bypassuac", "fodhelper", "eventvwr",
    "sdclt", "computerdefaults", "cmstp",
]

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
    '.pw', '.cc', '.su', '.ws', '.to', '.bz',
    '.click', '.link', '.download', '.stream',
}

C2_PATTERNS = [
    b"User-Agent:", b"GET / HTTP", b"POST /", b"Content-Type:",
    b"Mozilla/", b"cmd.exe /c", b"powershell -", b"certutil",
]

# ─── PE section analysis ─────────────────────────────────────
KNOWN_GOOD_SECTIONS = {'.text', '.data', '.rdata', '.rsrc', '.reloc', '.pdata',
                        '.bss', '.idata', '.edata', '.tls', '.debug', '.xdata'}

PE_SUSPICIOUS_IMPORTS = {
    # Credential theft
    "SamOpenDatabase", "SamGetPrivateData", "NlpGetPrimaryCredential",
    "LsaIEnumerateSecrets", "CredEnumerate",
    # Keylogging
    "GetAsyncKeyState", "SetWindowsHookEx", "GetForegroundWindow",
    # Screen capture
    "BitBlt", "GetDC", "CreateCompatibleDC",
    # Clipboard
    "OpenClipboard", "GetClipboardData",
    # Network raw
    "WSASocket", "bind", "listen", "accept",
    # Token manipulation
    "OpenProcessToken", "DuplicateTokenEx",
}

COMPILER_SIGNATURES = {
    b"Microsoft Visual C++": "MSVC",
    b"GCC: (":               "GCC",
    b"LLVM":                 "Clang/LLVM",
    b"Borland":              "Borland/Delphi",
    b"AutoIt":               "AutoIt Script",
    b"NSIS":                 "NSIS Installer",
    b"Inno Setup":           "Inno Setup",
    b"PyInstaller":          "PyInstaller (Python packed)",
    b"cx_Freeze":            "cx_Freeze (Python packed)",
    b"py2exe":               "py2exe (Python packed)",
    b"Nullsoft":             "NSIS",
}

# ─── Non-linear scoring config ───────────────────────────────
SCORE_NONLINEAR = {
    # Sigmoid steepness: higher = sharper transition at midpoints
    "sigmoid_k":       8.0,
    # Pivot score where risk escalates fast
    "sigmoid_mid":     0.42,
    # Threat amplifier: if N modules all detect, multiply by this
    "consensus_bonus": 1.35,
    "consensus_min_modules": 3,
    # Individual finding caps
    "finding_cap":     95,
}

# ─── Cache defaults ─────────────────────────────────────────
CACHE_DEFAULTS = {
    "max_ram_gb":   0.5,
    "max_disk_gb":  2.0,
    "ttl_static_h": 168,  # 7 days
    "ttl_vt_h":     24,
    "ttl_sandbox_h":12,
    "store_in_ram":  True,
    "store_on_disk": True,
    "disk_path":     "",   # auto = %APPDATA%\HardFileAnalyzer\cache
}

# ─── VirusTotal ──────────────────────────────────────────────
VIRUSTOTAL_API = "https://www.virustotal.com/api/v3"

# ─── Sandbox config ──────────────────────────────────────────
SANDBOX_DEFAULTS = {
    "timeout_s":         30,
    "poll_interval_ms":  500,
    "watch_dirs":        [
        "%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
        "%SYSTEMROOT%\\System32", "%SYSTEMROOT%\\SysWOW64",
        "%PROGRAMFILES%", "%PROGRAMFILES(X86)%",
        "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Documents",
    ],
    "watch_registry":    True,
    "capture_network":   True,
    "kill_after":        True,
    "max_child_procs":   20,
}

EXECUTABLE_EXTS = {
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs',
    '.js', '.msi', '.com', '.pif', '.scr', '.cpl',
    '.hta', '.wsf', '.wsh', '.reg',
}