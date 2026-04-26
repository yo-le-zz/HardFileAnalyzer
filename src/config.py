# ============================================================
#  HARD FILE ANALYZER — config.py
#  Constantes, thème, modules, patterns, scoring
# ============================================================

APP_VERSION = "1.0.0"
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
    "static":    {"name": "Statique",     "desc": "Hash · Entropie · Structure · Strings · Metadata", "icon": "🔬", "tpm": 0.5,  "default": True},
    "heuristic": {"name": "Heuristique",  "desc": "Obfuscation · Ransomware · Injection · Anti-debug", "icon": "🧠", "tpm": 1.0,  "default": True},
    "network":   {"name": "Réseau",       "desc": "URLs · IPs encodées · Domaines suspects · C2",     "icon": "🌐", "tpm": 0.3,  "default": True},
    "system":    {"name": "Système",      "desc": "Fichiers sensibles · Registre · Élévation · Boot", "icon": "⚙️", "tpm": 0.5,  "default": True},
    "iq":        {"name": "IQ Mode",      "desc": "Incohérences logiques · Dates · Structure · Meta", "icon": "🧩", "tpm": 0.4,  "default": True},
    "cloud":     {"name": "Cloud (VT)",   "desc": "VirusTotal hash · Upload · Score multi-AV",        "icon": "☁️", "tpm": 5.0,  "default": False},
    "sandbox":   {"name": "Sandbox",      "desc": "Exécution isolée · Processus · Réseau · API calls","icon": "📦", "tpm": 10.0, "default": False},
}

# ─── Magic bytes → file type ─────────────────────────────────
MAGIC_SIGS = {
    b'\x4d\x5a':         "PE Executable",
    b'\x7f\x45\x4c\x46':"ELF Binary",
    b'\x25\x50\x44\x46':"PDF",
    b'\x50\x4b\x03\x04':"ZIP Archive",
    b'\x52\x61\x72\x21':"RAR Archive",
    b'\x1f\x8b':         "GZip",
    b'\x42\x5a\x68':     "BZip2",
    b'\xd0\xcf\x11\xe0':"OLE2 (MS Office)",
    b'\x89\x50\x4e\x47':"PNG",
    b'\xff\xd8\xff':     "JPEG",
    b'\x47\x49\x46\x38':"GIF",
    b'\x23\x21':         "Script (shebang)",
    b'\xca\xfe\xba\xbe':"Mach-O Binary",
    b'\x7b\x5c\x72\x74':"RTF",
    b'\xd4\xc3\xb2\xa1':"PCAP",
    b'\x4f\x67\x67\x53':"OGG",
    b'\x00\x00\x01\xba':"MPEG Stream",
    b'\x49\x44\x33':     "MP3",
    b'\x66\x4c\x61\x43':"FLAC",
    b'\x38\x42\x50\x53':"PSD",
}

PACKER_SIGS = [b'UPX0', b'UPX1', b'MPRESS', b'.aspack', b'.aPLib', b'PEC2TO', b'FSG!', b'PEPACK', b'Themida']

EXT_EXPECTED = {
    '.exe': ["PE Executable"], '.dll': ["PE Executable"], '.sys': ["PE Executable"],
    '.pdf': ["PDF"], '.jpg': ["JPEG"], '.jpeg': ["JPEG"], '.png': ["PNG"],
    '.gif': ["GIF"], '.zip': ["ZIP"], '.rar': ["RAR"], '.gz': ["GZip"],
    '.docx': ["ZIP"], '.xlsx': ["ZIP"], '.pptx': ["ZIP"],
    '.mp3': ["MP3"], '.ogg': ["OGG"], '.flac': ["FLAC"],
    '.psd': ["PSD"], '.pcap': ["PCAP"],
    '.rtf': ["RTF"], '.bat': ["Script", "text"], '.cmd': ["Script", "text"],
    '.ps1': ["Script", "text", "UTF"], '.vbs': ["Script", "text"],
    '.py':  ["Script", "text"], '.js':  ["Script", "text"],
}

# ─── Suspicious string patterns ──────────────────────────────
SUSPICIOUS_STRINGS = [
    # Registry persistence
    "CurrentVersion\\Run", "CurrentVersion\\RunOnce", "Winlogon\\Shell",
    "Winlogon\\Userinit", "SYSTEM\\CurrentControlSet\\Services",
    # Code injection APIs
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread", "SetWindowsHookEx",
    "QueueUserAPC", "NtQueueApcThread",
    # Anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "VBOX", "VMWARE", "VirtualBox", "vboxservice", "vmtoolsd",
    # Obfuscation
    "FromBase64String", "EncodedCommand", "-enc ", "powershell -",
    "WScript.Shell", "mshta", "regsvr32", "rundll32",
    # Credential theft
    "lsass", "SAMKey", "NTHash", "mimikatz", "sekurlsa",
    # Network C2
    "InternetOpenUrl", "HttpSendRequest", "WinHttpConnect",
    "curl ", "wget ", "Invoke-WebRequest",
    # Ransomware
    "encrypt", "decrypt", "ransom", "bitcoin", "wallet",
    "vssadmin delete", "bcdedit /set", "wbadmin delete",
    # Privilege escalation
    "SeDebugPrivilege", "AdjustTokenPrivileges", "ImpersonateLoggedOnUser",
    "CreateProcessWithTokenW",
    # Sensitive paths
    "\\SAM", "\\ntds.dit", "\\lsass.exe", "\\hosts",
    "\\System32\\drivers\\etc",
]

RANSOMWARE_BYTES = [
    b"encrypt", b"ransom", b"bitcoin", b"YOUR FILES", b"your files",
    b".locked", b".encrypted", b"DECRYPT_INSTRUCTION", b"HELP_DECRYPT",
    b"shadow", b"vssadmin", b"bcdedit", b"wbadmin", b"AES-256", b"RSA-2048",
]

SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw',
                   '.cc', '.su', '.ws', '.to', '.bz', '.io'}

# ─── Scoring weights ─────────────────────────────────────────
W = {
    "high_entropy":             20,
    "ext_mismatch_high":        25,
    "ext_mismatch_med":         12,
    "packed":                   15,
    "suspicious_str_few":        5,
    "suspicious_str_many":      15,
    "ransomware":               40,
    "code_injection":           25,
    "anti_debug":               20,
    "anti_vm":                  20,
    "persistence":              20,
    "privesc":                  25,
    "obfuscation":              10,
    "driver_load":              30,
    "sensitive_files":          20,
    "c2_patterns":              20,
    "ip_external":              10,
    "suspicious_domain":        15,
    "iq_temporal":              10,
    "iq_structure":             15,
    "iq_metadata":              10,
    "iq_logical":               10,
    "vt_low":                   20,
    "vt_medium":                50,
    "vt_high":                  80,
    "sandbox_suspicious_api":   10,
    "sandbox_anti_vm":          20,
    "sandbox_network":          10,
}

VIRUSTOTAL_API = "https://www.virustotal.com/api/v3"