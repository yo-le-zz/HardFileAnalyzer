# ============================================================
#  HARD FILE ANALYZER — engine.py
#  Moteur d'analyse : C++ core via ctypes, IQ Deep,
#  cache intelligent RAM/Disque, scoring non-linéaire
# ============================================================

import os, re, sys, math, time, json, sqlite3, hashlib, struct
import threading, subprocess, ctypes, ctypes.util
from datetime import datetime, timedelta
from collections import OrderedDict, Counter
from typing import Callable, Optional, Any

from config import *

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ════════════════════════════════════════════════════════════
#  C++ CORE LOADER
# ════════════════════════════════════════════════════════════

class CoreDLL:
    """Wrapper ctypes vers core.dll — fallback Python si absent."""

    _lock = threading.Lock()
    _instance = None

    def __init__(self):
        self._dll = None
        self._available = False
        dll_path = os.path.join(os.path.dirname(__file__), "core.dll")
        if os.path.exists(dll_path):
            try:
                self._dll = ctypes.CDLL(dll_path)
                self._setup()
                self._available = True
            except Exception as e:
                print(f"[WARN] core.dll non chargeable : {e} — fallback Python")

    def _setup(self):
        d = self._dll
        # md5(data, len, hex_out)
        d.md5.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        d.md5.restype  = None
        # sha1
        d.sha1.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        d.sha1.restype  = None
        # sha256
        d.sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        d.sha256.restype  = None
        # entropy_mt
        d.entropy_mt.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        d.entropy_mt.restype  = ctypes.c_int32
        # entropy_regions
        d.entropy_regions.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32),
            ctypes.c_int32
        ]
        d.entropy_regions.restype = ctypes.c_int32
        # extract_strings
        d.extract_strings.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_int32, ctypes.c_int32
        ]
        d.extract_strings.restype = ctypes.c_int32
        # extract_wide_strings
        d.extract_wide_strings.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_int32, ctypes.c_int32
        ]
        d.extract_wide_strings.restype = ctypes.c_int32
        # scan_patterns
        d.scan_patterns.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_int32),
            ctypes.c_int32,
            ctypes.c_void_p, ctypes.c_int32,
        ]
        d.scan_patterns.restype = ctypes.c_int32
        # parse_pe
        d.parse_pe.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
        d.parse_pe.restype  = None
        # byte_freq
        d.byte_freq.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_int32)
        ]
        d.byte_freq.restype = None

    # ── Hashing ───────────────────────────────────────────

    def compute_hashes(self, data: bytes) -> dict:
        if self._available:
            buf = ctypes.create_string_buffer(65)
            out = {}
            for fn_name, alg in [("md5","md5"),("sha1","sha1"),("sha256","sha256")]:
                fn = getattr(self._dll, fn_name)
                fn(data, len(data), buf)
                out[alg] = buf.value.decode("ascii")
            return out
        else:
            return {
                "md5":    hashlib.md5(data).hexdigest(),
                "sha1":   hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
            }

    def entropy(self, data: bytes) -> float:
        if self._available:
            return self._dll.entropy_mt(data, len(data)) / 10000.0
        return _py_entropy(data)

    def entropy_regions(self, data: bytes, max_regions: int = 64):
        if not self._available:
            return _py_entropy_regions(data, max_regions)
        offsets   = (ctypes.c_int32 * max_regions)()
        entropies = (ctypes.c_int32 * max_regions)()
        n = self._dll.entropy_regions(data, len(data), offsets, entropies, max_regions)
        return [{"offset": f"0x{offsets[i]:08x}", "entropy": entropies[i]/10000.0}
                for i in range(n)]

    def extract_strings(self, data: bytes, max_s: int = 6000, min_len: int = 6) -> list:
        if self._available:
            slot = 514
            buf  = ctypes.create_string_buffer(max_s * slot)
            n    = self._dll.extract_strings(data, len(data), buf, max_s, min_len)
            out  = []
            for i in range(n):
                s = buf.raw[i*slot:(i+1)*slot].split(b'\n')[0].decode("latin-1","replace")
                if s: out.append(s)
            # Also extract wide strings
            w_buf = ctypes.create_string_buffer(max_s * slot)
            wn    = self._dll.extract_wide_strings(data, len(data), w_buf, max_s//2, min_len)
            for i in range(wn):
                s = w_buf.raw[i*slot:(i+1)*slot].split(b'\n')[0].decode("latin-1","replace")
                if s: out.append("[W] " + s)
            return out
        return _py_extract_strings(data, max_s, min_len)

    def parse_pe(self, data: bytes) -> dict:
        if not self._available:
            return _py_pe_parse(data)
        # PEInfo struct layout (must match C++ exactly)
        class PEInfo(ctypes.Structure):
            _fields_ = [
                ("valid",          ctypes.c_int32),
                ("timestamp",      ctypes.c_uint32),
                ("machine",        ctypes.c_uint32),
                ("num_sections",   ctypes.c_uint16),
                ("entry_point",    ctypes.c_uint32),
                ("image_base_lo",  ctypes.c_uint32),
                ("has_overlay",    ctypes.c_int32),
                ("overlay_entropy_x10000", ctypes.c_int32),
                ("characteristics",ctypes.c_uint32),
                ("sec_count",      ctypes.c_int32),
                ("sec_names",      ctypes.c_char * (32*10)),
                ("sec_chars",      ctypes.c_uint32 * 32),
                ("sec_entropy",    ctypes.c_int32  * 32),
                ("file_checksum",  ctypes.c_uint32),
                ("checksum_valid", ctypes.c_int32),
            ]
        info = PEInfo()
        self._dll.parse_pe(data, len(data), ctypes.byref(info))
        if not info.valid: return {"valid": False}
        secs = []
        for i in range(min(info.sec_count, 32)):
            name = info.sec_names[i*10:(i+1)*10].rstrip(b'\x00').decode("ascii","replace")
            secs.append({
                "name":    name,
                "chars":   info.sec_chars[i],
                "entropy": info.sec_entropy[i] / 10000.0,
            })
        return {
            "valid":       True,
            "timestamp":   info.timestamp,
            "machine":     hex(info.machine),
            "num_sections":info.num_sections,
            "entry_point": hex(info.entry_point),
            "image_base":  hex(info.image_base_lo),
            "has_overlay": bool(info.has_overlay),
            "overlay_entropy": info.overlay_entropy_x10000 / 10000.0,
            "characteristics": info.characteristics,
            "sections":    secs,
            "checksum":    info.file_checksum,
        }

    def byte_freq(self, data: bytes):
        if not self._available:
            c = Counter(data)
            return [c.get(i,0) for i in range(256)], 0
        freq = (ctypes.c_uint32 * 256)()
        chi  = ctypes.c_int32(0)
        self._dll.byte_freq(data, len(data), freq, ctypes.byref(chi))
        return list(freq), chi.value / 100.0

CORE = CoreDLL()


# ════════════════════════════════════════════════════════════
#  PYTHON FALLBACKS
# ════════════════════════════════════════════════════════════

def _py_entropy(data: bytes) -> float:
    if not data: return 0.0
    c = Counter(data)
    t = len(data)
    return round(-sum((v/t)*math.log2(v/t) for v in c.values()), 4)

def _py_entropy_regions(data: bytes, max_r: int = 64) -> list:
    out, step = [], 65536
    for i in range(0, min(len(data), max_r*step), step):
        e = _py_entropy(data[i:i+step])
        if e > 7.0: out.append({"offset": f"0x{i:08x}", "entropy": e})
        if len(out) >= max_r: break
    return out

def _py_extract_strings(data: bytes, max_s: int = 6000, min_len: int = 6) -> list:
    out, cur = [], ""
    for b in data:
        c = chr(b)
        if c.isprintable() and c not in "\r\n":
            cur += c
        else:
            if len(cur) >= min_len: out.append(cur)
            cur = ""
            if len(out) >= max_s: break
    return out

def _py_pe_parse(data: bytes) -> dict:
    if len(data) < 64 or data[:2] != b'MZ': return {"valid": False}
    try:
        pe_off = struct.unpack_from("<I", data, 0x3c)[0]
        if data[pe_off:pe_off+4] != b'PE\x00\x00': return {"valid": False}
        ts = struct.unpack_from("<I", data, pe_off+8)[0]
        nsec = struct.unpack_from("<H", data, pe_off+6)[0]
        return {"valid": True, "timestamp": ts, "num_sections": nsec,
                "sections": [], "has_overlay": False}
    except: return {"valid": False}


# ════════════════════════════════════════════════════════════
#  CACHE MANAGER
# ════════════════════════════════════════════════════════════

class CacheManager:
    """
    LRU RAM cache + SQLite disk cache.
    Config runtime: max_ram_gb, max_disk_gb.
    """

    def __init__(self, cfg: dict):
        self.cfg          = {**CACHE_DEFAULTS, **cfg}
        self._ram         = OrderedDict()
        self._ram_bytes   = 0
        self._lock        = threading.RLock()
        self._disk_path   = self._resolve_disk_path()
        self._db: Optional[sqlite3.Connection] = None
        if self.cfg["store_on_disk"]:
            self._init_db()

    def _resolve_disk_path(self) -> str:
        p = self.cfg.get("disk_path","").strip()
        if not p:
            app = os.environ.get("APPDATA", os.path.expanduser("~"))
            p = os.path.join(app, "HardFileAnalyzer", "cache")
        os.makedirs(p, exist_ok=True)
        return p

    def _init_db(self):
        db_file = os.path.join(self._disk_path, "hfa_cache.sqlite3")
        self._db = sqlite3.connect(db_file, check_same_thread=False)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL,
                ts_expire REAL NOT NULL,
                size_bytes INTEGER NOT NULL
            )""")
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_exp ON cache(ts_expire)")
        self._db.commit()
        self._evict_expired_disk()

    # ── Key helpers ───────────────────────────────────────

    @staticmethod
    def file_key(path: str, modules: dict) -> str:
        try:
            st = os.stat(path)
            sig = f"{path}|{st.st_size}|{st.st_mtime}|{sorted(k for k,v in modules.items() if v)}"
        except:
            sig = path
        return hashlib.sha256(sig.encode()).hexdigest()

    @staticmethod
    def vt_key(sha256: str) -> str:
        return "vt_" + sha256

    # ── RAM cache ─────────────────────────────────────────

    def _ram_max_bytes(self) -> int:
        return int(self.cfg["max_ram_gb"] * 1024**3)

    def _ram_put(self, key: str, value: Any, ttl_h: float):
        if not self.cfg["store_in_ram"]: return
        data = json.dumps(value, default=str).encode()
        sz   = len(data)
        cap  = self._ram_max_bytes()
        with self._lock:
            # Evict LRU until enough space
            while self._ram_bytes + sz > cap and self._ram:
                _, (_, old_sz, _) = self._ram.popitem(last=False)
                self._ram_bytes -= old_sz
            expire = time.time() + ttl_h * 3600
            self._ram[key] = (data, sz, expire)
            self._ram_bytes += sz
            self._ram.move_to_end(key)

    def _ram_get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._ram: return None
            data, sz, expire = self._ram[key]
            if time.time() > expire:
                del self._ram[key]
                self._ram_bytes -= sz
                return None
            self._ram.move_to_end(key)
            return json.loads(data)

    # ── Disk cache ────────────────────────────────────────

    def _disk_max_bytes(self) -> int:
        return int(self.cfg["max_disk_gb"] * 1024**3)

    def _disk_put(self, key: str, value: Any, ttl_h: float):
        if not self.cfg["store_on_disk"] or not self._db: return
        data = json.dumps(value, default=str).encode()
        sz   = len(data)
        expire = time.time() + ttl_h * 3600
        try:
            with self._lock:
                self._db.execute(
                    "INSERT OR REPLACE INTO cache VALUES (?,?,?,?)",
                    (key, data, expire, sz))
                self._db.commit()
                self._evict_disk_if_full()
        except: pass

    def _disk_get(self, key: str) -> Optional[Any]:
        if not self.cfg["store_on_disk"] or not self._db: return None
        try:
            with self._lock:
                row = self._db.execute(
                    "SELECT value, ts_expire FROM cache WHERE key=?", (key,)).fetchone()
                if not row: return None
                if time.time() > row[1]:
                    self._db.execute("DELETE FROM cache WHERE key=?", (key,))
                    self._db.commit()
                    return None
                return json.loads(row[0])
        except: return None

    def _evict_expired_disk(self):
        if not self._db: return
        try:
            self._db.execute("DELETE FROM cache WHERE ts_expire < ?", (time.time(),))
            self._db.commit()
        except: pass

    def _evict_disk_if_full(self):
        if not self._db: return
        try:
            row = self._db.execute("SELECT SUM(size_bytes) FROM cache").fetchone()
            total = row[0] or 0
            cap   = self._disk_max_bytes()
            if total > cap:
                # Delete oldest by expiry
                excess = total - cap
                rows = self._db.execute(
                    "SELECT key, size_bytes FROM cache ORDER BY ts_expire ASC"
                ).fetchall()
                del_keys, freed = [], 0
                for k, sz in rows:
                    del_keys.append(k); freed += sz
                    if freed >= excess: break
                self._db.executemany("DELETE FROM cache WHERE key=?", [(k,) for k in del_keys])
                self._db.commit()
        except: pass

    # ── Public API ────────────────────────────────────────

    def get(self, key: str) -> Optional[Any]:
        v = self._ram_get(key)
        if v is not None: return v
        v = self._disk_get(key)
        if v is not None:
            # Promote to RAM
            self._ram_put(key, v, 1.0)
        return v

    def put(self, key: str, value: Any, ttl_h: float = 24.0):
        self._ram_put(key, value, ttl_h)
        self._disk_put(key, value, ttl_h)

    def stats(self) -> dict:
        with self._lock:
            ram_mb  = self._ram_bytes / 1024**2
            ram_cap = self.cfg["max_ram_gb"] * 1024
            n_ram   = len(self._ram)
        disk_mb, n_disk = 0, 0
        if self._db:
            try:
                r = self._db.execute("SELECT COUNT(*), SUM(size_bytes) FROM cache").fetchone()
                n_disk  = r[0] or 0
                disk_mb = (r[1] or 0) / 1024**2
            except: pass
        return {
            "ram_mb": round(ram_mb, 2), "ram_cap_mb": round(ram_cap, 2),
            "n_ram": n_ram, "disk_mb": round(disk_mb, 2),
            "disk_cap_gb": self.cfg["max_disk_gb"], "n_disk": n_disk,
        }

    def clear(self):
        with self._lock:
            self._ram.clear()
            self._ram_bytes = 0
        if self._db:
            self._db.execute("DELETE FROM cache")
            self._db.commit()


# Global cache — initialized by UI with user config
_cache: Optional[CacheManager] = None

def init_cache(cfg: dict):
    global _cache
    _cache = CacheManager(cfg)

def get_cache() -> CacheManager:
    global _cache
    if _cache is None:
        _cache = CacheManager({})
    return _cache


# ════════════════════════════════════════════════════════════
#  UTILITIES
# ════════════════════════════════════════════════════════════

def _human_size(b: int) -> str:
    for u in ["B","KB","MB","GB"]:
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

def _fmt_time(s: float) -> str:
    if s < 60:  return f"{int(s)}s"
    if s < 3600: return f"{int(s//60)}m {int(s%60)}s"
    return f"{int(s//3600)}h {int((s%3600)//60)}m"

def _read(path: str, max_mb: int = 100) -> bytes:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        return f.read(min(size, max_mb * 1024 * 1024))

def _ts_to_dt(ts: int) -> Optional[datetime]:
    try: return datetime.fromtimestamp(ts)
    except: return None


# ════════════════════════════════════════════════════════════
#  1 · STATIC ANALYSIS (C++ accelerated)
# ════════════════════════════════════════════════════════════

def detect_magic(data: bytes) -> str:
    for sig, t in MAGIC_SIGS.items():
        if data[:len(sig)] == sig:
            return t
    return "Unknown"

def detect_packer(data: bytes) -> tuple:
    for p in PACKER_SIGS:
        if p in data: return True, p.decode("latin-1")
    return False, ""

def static_analysis(path: str, cb: Callable) -> dict:
    cb("🔬 Lecture du fichier en mémoire…")
    data = _read(path)
    cb("🔬 Calcul hashes via C++ (MD5/SHA1/SHA256)…")
    hashes = CORE.compute_hashes(data)

    cb("🔬 Analyse magic bytes + détection packer…")
    ftype_str = detect_magic(data)
    packed, packer = detect_packer(data)
    # High-entropy check for unknown packer
    global_ent = CORE.entropy(data)
    if not packed and global_ent > 7.2 and ftype_str == "PE Executable":
        packed, packer = True, "Unknown (high entropy)"

    cb("🔬 Vérification extension ↔ contenu réel…")
    ext     = os.path.splitext(path)[1].lower()
    expected = EXT_EXPECTED.get(ext, [])
    mismatch = bool(expected and not any(e.lower() in ftype_str.lower() for e in expected))
    mismatch_severity = "none"
    if mismatch and ftype_str != "Unknown":
        crit = {'.jpg','.jpeg','.png','.gif','.bmp','.txt','.pdf','.docx','.xlsx'}
        mismatch_severity = "high" if ext in crit and "PE" in ftype_str else "medium"

    cb("🔬 Analyse entropie multithreadée (chunks 64KB)…")
    regions = CORE.entropy_regions(data)

    cb("🔬 Extraction strings ASCII + Wide (C++ multithreadé)…")
    all_strings = CORE.extract_strings(data)
    cb("🔬 Matching patterns suspects…")
    sus_strings = []
    seen = set()
    for s in all_strings:
        sl = s.lower()
        for pat in SUSPICIOUS_STRINGS if hasattr(sys.modules.get('config',None),'SUSPICIOUS_STRINGS') \
                else _build_suspicious():
            if pat.lower() in sl and pat not in seen:
                sus_strings.append({"string": s[:120], "pattern": pat})
                seen.add(pat)
                break

    cb("🔬 Analyse fréquence octets (chi-carré)…")
    bfreq, chi_sq = CORE.byte_freq(data)

    cb("🔬 Extraction métadonnées OS…")
    meta = _extract_metadata(path)

    cb("🔬 Parsing PE (si applicable)…")
    pe_info = {}
    if ftype_str == "PE Executable":
        cb("🔬 Parsing structure PE (sections / timestamps / overlay)…")
        pe_info = CORE.parse_pe(data)

    # Compiler signature detection
    compiler = "Unknown"
    for sig, name in COMPILER_SIGNATURES.items():
        if sig in data: compiler = name; break

    # Score
    score = 0
    findings = []
    if global_ent > 7.2:
        score += 20; findings.append(("Entropie globale critique", "HIGH", global_ent))
    elif global_ent > 6.8:
        score += 10; findings.append(("Entropie globale élevée", "MEDIUM", global_ent))
    if mismatch_severity == "high":
        score += 25; findings.append(("Extension MISMATCH critique", "CRITICAL", ext))
    elif mismatch_severity == "medium":
        score += 12; findings.append(("Extension MISMATCH modéré", "MEDIUM", ext))
    if packed:
        score += 15; findings.append((f"Packer détecté: {packer}", "HIGH", packer))
    n_sus = len(sus_strings)
    if n_sus > 15: score += 15; findings.append((f"{n_sus} strings suspects", "HIGH", n_sus))
    elif n_sus > 5: score += 7; findings.append((f"{n_sus} strings suspects", "MEDIUM", n_sus))
    if len(regions) > 3: score += 10; findings.append(("Multiples régions haute entropie", "MEDIUM", len(regions)))

    return {
        "hashes": hashes, "type": ftype_str, "packed": packed, "packer": packer,
        "extension": ext, "mismatch": mismatch, "mismatch_severity": mismatch_severity,
        "entropy_global": global_ent, "entropy_regions": regions,
        "strings_total": len(all_strings), "strings_suspicious": sus_strings[:80],
        "pe": pe_info, "compiler": compiler,
        "byte_chi_sq": chi_sq, "metadata": meta,
        "findings": findings, "score": min(score, 100),
    }

def _build_suspicious():
    from config import SUSPICIOUS_STRINGS as SS
    return SS

SUSPICIOUS_STRINGS = [
    "CurrentVersion\\Run","CurrentVersion\\RunOnce","Winlogon\\Shell",
    "VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
    "IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
    "VBOX","VMWARE","VirtualBox","vboxservice","vmtoolsd",
    "FromBase64String","EncodedCommand","-enc ","WScript.Shell","mshta",
    "lsass","SAMKey","NTHash","mimikatz","sekurlsa",
    "InternetOpenUrl","HttpSendRequest","WinHttpConnect",
    "encrypt","decrypt","ransom","bitcoin","wallet",
    "vssadmin delete","bcdedit /set","wbadmin delete",
    "SeDebugPrivilege","AdjustTokenPrivileges","ImpersonateLoggedOnUser",
    "\\SAM","\\ntds.dit","\\lsass.exe","\\hosts",
    "cmd /c","powershell -","certutil","regsvr32","rundll32",
    "AppInit_DLLs","Image File Execution Options","Debugger",
]

def _extract_metadata(path: str) -> dict:
    st = os.stat(path)
    meta = {
        "filename":   os.path.basename(path),
        "path":       path,
        "extension":  os.path.splitext(path)[1].lower(),
        "size_bytes": st.st_size,
        "size_human": _human_size(st.st_size),
        "created":    datetime.fromtimestamp(st.st_ctime).isoformat(),
        "modified":   datetime.fromtimestamp(st.st_mtime).isoformat(),
        "accessed":   datetime.fromtimestamp(st.st_atime).isoformat(),
        "signature":  "Unknown",
    }
    try:
        r = subprocess.run(
            ["powershell","-NoProfile","-Command",
             f'(Get-AuthenticodeSignature "{path}").Status'],
            capture_output=True, text=True, timeout=5)
        meta["signature"] = r.stdout.strip() or "Unknown"
    except: pass
    return meta


# ════════════════════════════════════════════════════════════
#  2 · HEURISTIC ANALYSIS
# ════════════════════════════════════════════════════════════

def heuristic_analysis(path: str, cb: Callable) -> dict:
    data = _read(path)
    ds   = data.decode("latin-1", errors="replace")
    result = {"ransomware":[],"injection":[],"anti_debug":[],"anti_vm":[],
              "persistence":[],"privesc":[],"obfuscation":False,
              "credential_theft":[],"network_apis":[],"suspicious_imports":[],
              "findings":[], "score": 0}

    cb("🧠 Scan patterns ransomware (C++ pattern matching)…")
    for p in RANSOMWARE_BYTES:
        if p in data: result["ransomware"].append(p.decode("latin-1"))

    cb("🧠 Détection APIs code injection…")
    for api in CODE_INJECTION_APIS:
        if api.encode() in data or api in ds: result["injection"].append(api)

    cb("🧠 Détection anti-debug / anti-analyse…")
    for api in ANTI_DEBUG_APIS:
        if api.encode() in data or api in ds: result["anti_debug"].append(api)

    cb("🧠 Détection anti-VM / anti-sandbox…")
    for vm in ANTI_VM_STRINGS:
        if vm.encode() in data or vm in ds: result["anti_vm"].append(vm)

    cb("🧠 Détection persistence / startup…")
    for p in PERSISTENCE_PATTERNS:
        if p in ds: result["persistence"].append(p)

    cb("🧠 Détection élévation de privilèges…")
    for p in PRIVESC_PATTERNS:
        if p.encode() in data or p.lower() in ds.lower(): result["privesc"].append(p)

    cb("🧠 Détection vol credentials…")
    for api in PE_SUSPICIOUS_IMPORTS:
        if api in ds: result["credential_theft"].append(api)

    cb("🧠 Détection obfuscation…")
    if re.search(rb'[A-Za-z0-9+/]{100,}={0,2}', data): result["obfuscation"] = True
    if re.search(r'(\\x[0-9a-fA-F]{2}){12,}', ds):    result["obfuscation"] = True
    if re.search(rb'(%[0-9a-fA-F]{2}){15,}', data):    result["obfuscation"] = True

    cb("🧠 Détection APIs réseau…")
    for api in ["InternetOpenUrl","HttpSendRequest","WinHttpConnect",
                "WSASocket","socket","bind","connect","send","recv",
                "InternetConnect","InternetReadFile","InternetWriteFile"]:
        if api.encode() in data: result["network_apis"].append(api)

    # Score
    f, s = result["findings"], 0
    if result["ransomware"]:      s += 45; f.append(("Ransomware patterns","CRITICAL"))
    if result["injection"]:       s += 30; f.append((f"Code injection ({len(result['injection'])} APIs)","HIGH"))
    if result["anti_debug"]:      s += 20; f.append((f"Anti-debug ({len(result['anti_debug'])})","HIGH"))
    if result["anti_vm"]:         s += 20; f.append((f"Anti-VM ({', '.join(result['anti_vm'][:2])})","HIGH"))
    if result["persistence"]:     s += 20; f.append(("Persistence détectée","HIGH"))
    if result["privesc"]:         s += 25; f.append(("Élévation privilèges","HIGH"))
    if result["credential_theft"]:s += 20; f.append(("Vol credentials","HIGH"))
    if result["obfuscation"]:     s += 12; f.append(("Obfuscation détectée","MEDIUM"))
    result["score"] = min(s, 100)
    return result


# ════════════════════════════════════════════════════════════
#  3 · NETWORK ANALYSIS (static)
# ════════════════════════════════════════════════════════════

def network_analysis(path: str, cb: Callable) -> dict:
    data = _read(path)
    ds   = data.decode("latin-1", errors="replace")
    out  = {"urls":[],"ips":[],"domains_suspicious":[],"b64_payloads":[],
            "c2_patterns":[],"onion":[],"findings":[],"score":0}

    cb("🌐 Extraction URLs…")
    out["urls"] = list(set(re.findall(
        r'https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]{5,80}', ds)))[:60]

    cb("🌐 Extraction IPs externes…")
    all_ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b', ds)
    out["ips"] = list(set(ip for ip in all_ips
        if not re.match(r'^(127\.|0\.0\.0\.|255\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)', ip)))[:40]

    cb("🌐 Détection domaines suspects / TLDs malveillants…")
    for d in set(re.findall(r'[a-zA-Z0-9\-]{3,63}\.[a-zA-Z]{2,}', ds)):
        for tld in SUSPICIOUS_TLDS:
            if d.lower().endswith(tld): out["domains_suspicious"].append(d); break
    out["domains_suspicious"] = out["domains_suspicious"][:30]

    cb("🌐 Détection services .onion (Tor)…")
    out["onion"] = re.findall(r'[a-z2-7]{16,56}\.onion', ds)[:10]

    cb("🌐 Détection payloads base64 / C2 patterns…")
    out["b64_payloads"] = [m.decode("ascii","replace")[:80]
                           for m in re.findall(rb'[A-Za-z0-9+/]{120,}={0,2}', data)][:10]
    for p in C2_PATTERNS:
        if p in data: out["c2_patterns"].append(p.decode("latin-1"))

    s, f = 0, out["findings"]
    if out["ips"]:                s += 10; f.append((f"{len(out['ips'])} IPs externes","MEDIUM"))
    if out["domains_suspicious"]: s += 15; f.append((f"{len(out['domains_suspicious'])} domaines suspects","HIGH"))
    if out["onion"]:              s += 25; f.append((f"{len(out['onion'])} domaine(s) .onion Tor","CRITICAL"))
    if out["b64_payloads"]:       s += 20; f.append(("Payloads base64 suspects","HIGH"))
    if out["c2_patterns"]:        s += 20; f.append(("Patterns C2 détectés","HIGH"))
    out["score"] = min(s, 100)
    return out


# ════════════════════════════════════════════════════════════
#  4 · SYSTEM ANALYSIS (static)
# ════════════════════════════════════════════════════════════

def system_analysis(path: str, cb: Callable) -> dict:
    data = _read(path)
    ds   = data.decode("latin-1", errors="replace")
    out  = {"sensitive_files":[],"registry_keys":[],"privilege_req":False,
            "startup":False,"driver_load":False,"suspicious_services":[],
            "uac_bypass":[],"findings":[],"score":0}

    cb("⚙️ Analyse accès fichiers système sensibles…")
    for f in ["\\SAM","\\SYSTEM","\\SECURITY","\\ntds.dit","\\lsass.exe",
              "\\winlogon.exe","\\services.exe","\\drivers\\etc\\hosts",
              "\\System32\\config\\","shadow copy","\\system.ini","\\win.ini"]:
        if f in ds: out["sensitive_files"].append(f)

    cb("⚙️ Analyse clés registre persistance…")
    for k in ["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
              "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
              "HKLM\\SYSTEM\\CurrentControlSet\\Services",
              "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
              "AppInit_DLLs","Image File Execution Options","BootExecute"]:
        if k in ds or k.lower() in ds.lower(): out["registry_keys"].append(k)

    cb("⚙️ Détection élévation, drivers, services…")
    if any(p in ds for p in ["SeDebugPrivilege","OpenSCManager","CreateService","runas"]):
        out["privilege_req"] = True
    if any(p in ds for p in ["\\Startup\\","CurrentVersion\\Run","Winlogon\\Shell"]):
        out["startup"] = True
    if any(p in ds for p in ["NtLoadDriver","ZwLoadDriver","\\drivers\\",".sys\x00",
                              "CreateService","StartService"]):
        out["driver_load"] = True

    cb("⚙️ Détection bypass UAC…")
    for b in ["fodhelper","eventvwr","sdclt","computerdefaults","cmstp",
              "slui","wscript.exe","mshta.exe","eventvwr.exe"]:
        if b in ds.lower(): out["uac_bypass"].append(b)

    s, f = 0, out["findings"]
    if out["sensitive_files"]:  s += 20; f.append((f"{len(out['sensitive_files'])} fichiers système","HIGH"))
    if out["registry_keys"]:    s += 20; f.append(("Manipulation registre","HIGH"))
    if out["privilege_req"]:    s += 25; f.append(("Élévation privilèges système","HIGH"))
    if out["startup"]:          s += 20; f.append(("Persistence startup","HIGH"))
    if out["driver_load"]:      s += 30; f.append(("Chargement pilote kernel","CRITICAL"))
    if out["uac_bypass"]:       s += 25; f.append((f"UAC bypass: {', '.join(out['uac_bypass'][:2])}","CRITICAL"))
    out["score"] = min(s, 100)
    return out


# ════════════════════════════════════════════════════════════
#  5 · IQ MODE — Deep Logical Inconsistency Analysis
# ════════════════════════════════════════════════════════════

def iq_analysis(path: str, static_r: dict, cb: Callable) -> dict:
    out = {
        "temporal":[], "structure":[], "metadata_contra":[], "logical":[],
        "pe_anomalies":[], "filename_anomalies":[], "compiler_anomalies":[],
        "findings":[], "score":0,
    }
    data = _read(path)
    meta = static_r.get("metadata", {})
    pe   = static_r.get("pe", {})

    # ── 1. Temporal coherence ──────────────────────────────
    cb("🧩 IQ — Analyse temporelle avancée…")
    now = datetime.now()
    for key in ["created","modified","accessed"]:
        val = meta.get(key,"")
        if val:
            try:
                dt = datetime.fromisoformat(val)
                if dt > now:
                    out["temporal"].append(f"⚠️ Date {key} dans le futur ({dt.date()})")
                if dt.year < 1985:
                    out["temporal"].append(f"⚠️ Date {key} impossible ({dt.year})")
            except: pass

    try:
        cr = datetime.fromisoformat(meta.get("created",""))
        mo = datetime.fromisoformat(meta.get("modified",""))
        if mo < cr:
            out["temporal"].append("⚠️ Modification ANTÉRIEURE à la création (timestamp manipulé)")
        if (now - cr).days < 1 and os.path.getsize(path) > 10*1024*1024:
            out["temporal"].append("⚠️ Fichier très récent (< 24h) et volumineux — possible drop")
    except: pass

    if pe.get("valid"):
        ts = pe.get("timestamp",0)
        pe_dt = _ts_to_dt(ts)
        if pe_dt:
            if pe_dt > now:
                out["temporal"].append(f"⚠️ Timestamp PE dans le futur : {pe_dt.date()}")
            if pe_dt.year < 1995:
                out["temporal"].append(f"⚠️ Timestamp PE anormal : {pe_dt.year}")
            try:
                cr = datetime.fromisoformat(meta.get("created",""))
                delta = abs((pe_dt - cr).days)
                if delta > 365 * 5:
                    out["temporal"].append(
                        f"⚠️ Écart PE timestamp ↔ création fichier : {delta} jours")
            except: pass
        # Known fake timestamps
        if ts in [0, 0xffffffff, 1]:
            out["temporal"].append("⚠️ PE timestamp nul ou effacé volontairement")

    # ── 2. Structural coherence ────────────────────────────
    cb("🧩 IQ — Analyse structurelle profonde…")
    name = os.path.basename(path)
    ext  = meta.get("extension","")
    size = meta.get("size_bytes", 0)

    if data[:16] == b'\x00'*16 and size > 64:
        out["structure"].append("⚠️ Entête complètement nulle (signature effacée)")
    if size == 0:
        out["structure"].append("⚠️ Fichier vide (0 octets)")

    # Multiple extensions
    parts = name.split(".")
    if len(parts) > 2:
        out["structure"].append(f"⚠️ Extensions multiples suspectes : {name}")

    # RTLO / Unicode tricks
    for rtlo in RTLO_CHARS:
        if rtlo in name:
            out["filename_anomalies"].append(f"⚠️ RTLO (Right-to-Left Override) dans le nom : {repr(name)}")
            break
    for zw in ZERO_WIDTH:
        if zw in name:
            out["filename_anomalies"].append(f"⚠️ Caractère zero-width dans le nom : {repr(name)}")
            break

    # Homoglyph attack detection
    for char, look_alikes in HOMOGLYPHS.items():
        for la in look_alikes:
            if la in name:
                out["filename_anomalies"].append(f"⚠️ Homoglyphe suspect dans nom : '{la}' ressemble à '{char}'")

    # Filename entropy (high = random generated)
    n_ent = _py_entropy(name.encode()) if len(name) > 6 else 0
    if n_ent > 4.0 and len(name) > 12:
        out["filename_anomalies"].append(f"⚠️ Nom de fichier à entropie élevée ({n_ent:.2f}) — possible nom généré")

    # Very long filename
    if len(name) > 200:
        out["filename_anomalies"].append(f"⚠️ Nom de fichier très long ({len(name)} chars)")

    # Minimum size check
    min_sizes = {'.exe':1024,'.dll':1024,'.pdf':128,'.docx':500,'.zip':22,'.msi':4096}
    if ext in min_sizes and size < min_sizes[ext]:
        out["structure"].append(f"⚠️ Fichier {ext} anormalement petit ({size} octets)")

    # Tail entropy (overlay)
    if size > 4096:
        tail_ent = CORE.entropy(data[-4096:])
        if tail_ent > 7.5:
            out["structure"].append(f"⚠️ Données fin de fichier très haute entropie ({tail_ent:.2f}) — overlay chiffré")

    # Script extension but binary content
    if ext in {'.js','.py','.vbs','.bat','.ps1','.txt'} and data[:2] == b'MZ':
        out["logical"].append(f"⚠️ Extension {ext} (script) mais signature PE binaire détectée")

    # Zero byte density (padding / anti-scan)
    zero_ratio = data.count(0) / max(len(data), 1)
    if zero_ratio > 0.60:
        out["structure"].append(f"⚠️ {zero_ratio*100:.1f}% de bytes nuls — possible padding anti-scan")

    # ── 3. PE deep anomalies ───────────────────────────────
    cb("🧩 IQ — Analyse PE approfondie…")
    if pe.get("valid"):
        # Section names
        for sec in pe.get("sections",[]):
            sname = sec["name"].strip()
            # Non-standard section names
            if sname and sname not in KNOWN_GOOD_SECTIONS and sname.startswith("."):
                out["pe_anomalies"].append(f"⚠️ Section PE non standard : '{sname}'")
            # Executable + writable section = code injection preparation
            CHAR_EXEC  = 0x20000000
            CHAR_WRITE = 0x80000000
            if (sec["chars"] & CHAR_EXEC) and (sec["chars"] & CHAR_WRITE):
                out["pe_anomalies"].append(f"⚠️ Section '{sname}' : EXECUTE + WRITE (injection)")
            # High entropy code section (packed/encrypted)
            if sname == ".text" and sec["entropy"] > 7.0:
                out["pe_anomalies"].append(f"⚠️ Section .text entropie {sec['entropy']:.2f} (code chiffré)")
            # Zero-size sections
            if sname and sec["entropy"] == 0.0:
                out["pe_anomalies"].append(f"⚠️ Section '{sname}' entropie nulle (vide ou effacée)")

        # Overlay chiffré
        if pe.get("has_overlay") and pe.get("overlay_entropy",0) > 7.0:
            out["pe_anomalies"].append(
                f"⚠️ Overlay PE haute entropie ({pe['overlay_entropy']:.2f}) — payload caché")

        # Entry point anomaly
        ep = pe.get("entry_point","")
        # Entry in suspicious section (not .text)
        for sec in pe.get("sections",[]):
            if ".data" in sec["name"] or ".rsrc" in sec["name"]:
                # Can't check EP range without full VA, skip
                pass

    # ── 4. Metadata contradictions ─────────────────────────
    cb("🧩 IQ — Contradictions métadonnées / contenu…")
    sig = meta.get("signature","Unknown")
    if sig == "Valid" and static_r.get("packed"):
        out["metadata_contra"].append("⚠️ Fichier SIGNÉ mais packer détecté — signature invalide logiquement")

    detected_type = static_r.get("type","")
    if detected_type == "PDF":
        ent = static_r.get("entropy_global", 0)
        if ent > 7.5:
            out["metadata_contra"].append(f"⚠️ PDF entropie {ent:.2f} — stéganographie ou payload chiffré")

    # Compiler vs format
    compiler = static_r.get("compiler","Unknown")
    if "Python" in compiler and ext in {'.exe','.dll'}:
        out["compiler_anomalies"].append(f"⚠️ Compilateur Python ({compiler}) dans un binaire natif — packing")
    if "AutoIt" in compiler:
        out["compiler_anomalies"].append("⚠️ AutoIt détecté — souvent utilisé pour malware scriptés")
    if compiler == "Unknown" and detected_type == "PE Executable" and size > 64*1024:
        out["compiler_anomalies"].append("⚠️ Aucune signature compilateur dans PE non trivial")

    # ── 5. Logical anomalies ───────────────────────────────
    cb("🧩 IQ — Anomalies logiques globales…")
    # Large file, almost no strings
    n_str = static_r.get("strings_total", 0)
    if size > 100*1024 and n_str < 15:
        out["logical"].append("⚠️ Fichier volumineux avec très peu de strings (chiffrement total probable)")

    # High entropy but small file (dropper?)
    if size < 50*1024 and static_r.get("entropy_global",0) > 7.3:
        out["logical"].append("⚠️ Petit fichier à très haute entropie (dropper chiffré probable)")

    # Check if the claimed filetype chi-sq is inconsistent
    if static_r.get("byte_chi_sq",0) > 50000:
        out["logical"].append("⚠️ Distribution octets aberrante (chi² élevé) — données artificielles ou chiffrées")

    # ── Score ──────────────────────────────────────────────
    s, f = 0, out["findings"]
    cats = [
        (out["temporal"],          10, "Anomalies temporelles"),
        (out["structure"],         15, "Anomalies structure"),
        (out["metadata_contra"],   12, "Contradictions metadata"),
        (out["logical"],           12, "Anomalies logiques"),
        (out["pe_anomalies"],      15, "Anomalies PE"),
        (out["filename_anomalies"],20, "Attaques nom fichier"),
        (out["compiler_anomalies"],10, "Anomalies compilateur"),
    ]
    for items, w, label in cats:
        if items:
            s += min(len(items) * w, w * 3)
            f.append((f"{label} ({len(items)})", "MEDIUM" if w <= 12 else "HIGH"))

    out["score"] = min(s, 100)
    return out


# ════════════════════════════════════════════════════════════
#  6 · CLOUD — VirusTotal (with cache)
# ════════════════════════════════════════════════════════════

def virustotal(path: str, api_key: str, sha256_hash: str, cb: Callable) -> dict:
    result = {"checked":False,"found":False,"detections":0,"total":0,
              "rate":"0%","permalink":"","engines":{},"score":0,"from_cache":False}
    if not HAS_REQUESTS:
        result["error"] = "Module 'requests' manquant"; return result
    if not api_key:
        result["error"] = "Clé API VirusTotal non configurée"; return result

    # Check cache
    cache_key = CacheManager.vt_key(sha256_hash)
    cached = get_cache().get(cache_key)
    if cached:
        cb("☁️ Résultat VirusTotal depuis le cache…")
        cached["from_cache"] = True
        return cached

    headers = {"x-apikey": api_key}
    try:
        cb("☁️ Vérification hash SHA256 sur VirusTotal…")
        r = requests.get(f"{VIRUSTOTAL_API}/files/{sha256_hash}", headers=headers, timeout=14)
        if r.status_code == 200:
            attrs = r.json().get("data",{}).get("attributes",{})
            stats = attrs.get("last_analysis_stats",{})
            result["checked"] = result["found"] = True
            result["detections"] = stats.get("malicious",0) + stats.get("suspicious",0)
            result["total"]      = sum(stats.values())
            result["permalink"]  = f"https://www.virustotal.com/gui/file/{sha256_hash}"
            if result["total"]:
                result["rate"] = f"{result['detections']/result['total']*100:.1f}%"
            result["engines"] = {
                k: v.get("result","") for k,v in attrs.get("last_analysis_results",{}).items()
                if v.get("category") in ("malicious","suspicious")
            }
        elif r.status_code == 404:
            fsize = os.path.getsize(path)
            if fsize > 32*1024*1024:
                result["error"] = "Fichier >32 MB — upload non disponible"; return result
            cb("☁️ Hash inconnu — upload du fichier…")
            with open(path,"rb") as fp:
                up = requests.post(f"{VIRUSTOTAL_API}/files",
                                   headers=headers, files={"file":fp}, timeout=90)
            if up.status_code == 200:
                aid = up.json().get("data",{}).get("id","")
                result["checked"] = True
                result["permalink"] = f"https://www.virustotal.com/gui/file-analysis/{aid}"
                cb("☁️ Attente résultats (max 60s)…")
                for _ in range(12):
                    time.sleep(5)
                    p = requests.get(f"{VIRUSTOTAL_API}/analyses/{aid}",headers=headers,timeout=12)
                    if p.status_code == 200:
                        pd = p.json().get("data",{}).get("attributes",{})
                        if pd.get("status") == "completed":
                            st = pd.get("stats",{})
                            result["detections"] = st.get("malicious",0)+st.get("suspicious",0)
                            result["total"] = sum(st.values())
                            if result["total"]:
                                result["rate"] = f"{result['detections']/result['total']*100:.1f}%"
                            break
        else:
            result["error"] = f"API HTTP {r.status_code}"; return result

        d, t = result["detections"], result["total"]
        if t and d:
            pct = d/t
            if pct < 0.10:   result["score"] = 20
            elif pct < 0.25: result["score"] = 55
            else:            result["score"] = 85

        # Cache the result
        get_cache().put(cache_key, result, ttl_h=CACHE_DEFAULTS["ttl_vt_h"])
    except Exception as e:
        result["error"] = f"Erreur réseau : {e}"
    return result


# ════════════════════════════════════════════════════════════
#  NON-LINEAR SCORING
# ════════════════════════════════════════════════════════════

def _sigmoid(x: float, k: float = 8.0, mid: float = 0.42) -> float:
    return 1.0 / (1.0 + math.exp(-k * (x - mid)))

def final_score(results: dict, enabled: dict, dont_trust: bool) -> dict:
    """
    Scoring non-linéaire probabiliste.
    Modèle : P(malveillant) = 1 - Π(1 - w_i × s_i)
    puis passage par sigmoid pour amplifier les extremes.
    """
    module_scores = {}
    factors = []

    for mid, cfg in MODULES.items():
        if not enabled.get(mid) or mid not in results: continue
        s = results[mid].get("score", 0)
        module_scores[mid] = s
        # Collect findings
        for item in results[mid].get("findings", []):
            if isinstance(item, tuple) and len(item) >= 2:
                factors.append({"module": cfg["name"], "desc": item[0], "sev": item[1]})

    if not module_scores:
        return {"score":0,"label":"SAFE","color":C["green"],"icon":"✅","factors":[],"dont_trust":dont_trust}

    # P(clean) = product of P(clean per module)
    p_clean = 1.0
    for mid, raw_score in module_scores.items():
        w = MODULE_RELIABILITY.get(mid, 0.5)
        p_threat = w * (raw_score / 100.0)
        p_clean *= (1.0 - p_threat)

    raw_p = 1.0 - p_clean  # 0..1

    # Consensus bonus: if ≥ N modules all detect something, multiply risk
    detect_count = sum(1 for s in module_scores.values() if s > 20)
    if detect_count >= SCORE_NONLINEAR["consensus_min_modules"]:
        bonus = SCORE_NONLINEAR["consensus_bonus"]
        raw_p = min(raw_p * bonus, 0.99)

    # Apply sigmoid for non-linearity (steepen transitions)
    sig = _sigmoid(raw_p, k=SCORE_NONLINEAR["sigmoid_k"], mid=SCORE_NONLINEAR["sigmoid_mid"])
    final = min(int(sig * 100), 100)

    label, color, icon = get_risk(final)
    return {
        "score": final, "label": label, "color": color, "icon": icon,
        "factors": factors, "dont_trust": dont_trust,
        "module_scores": module_scores, "raw_probability": round(raw_p*100,2),
        "consensus_modules": detect_count,
    }


# ════════════════════════════════════════════════════════════
#  TIME ESTIMATION
# ════════════════════════════════════════════════════════════

def estimate_time(path: str, enabled: dict) -> dict:
    mb, count = 0.0, 0
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in files:
                fp = os.path.join(root, f)
                try: mb += os.path.getsize(fp)/1048576; count += 1
                except: pass
    else:
        try: mb = os.path.getsize(path)/1048576; count = 1
        except: pass
    mb = max(mb, 0.01)
    breakdown, total = {}, 0.0
    for mid, on in enabled.items():
        if on and mid in MODULES:
            t = max(MODULES[mid]["tpm"] * mb * max(count,1), 0.3)
            breakdown[mid] = round(t, 1); total += t
    return {"seconds":round(total,1),"human":_fmt_time(total),
            "files":count,"size_mb":round(mb,2),"breakdown":breakdown}


# ════════════════════════════════════════════════════════════
#  TRACKING MODE
# ════════════════════════════════════════════════════════════

def tracking_report(path: str, enabled: dict, vt_key: str) -> str:
    lines = [
        "═"*62,
        "  🔍  MODE TRACKING — RAPPORT PRÉ-ANALYSE COMPLET",
        "═"*62,
        f"  Cible     : {path}",
        f"  Horodatage: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Core C++  : {'✅ Disponible' if CORE._available else '⚠️ Fallback Python'}",
        "",
    ]
    order = 1
    descriptions = {
        "static": [
            "① Lecture binaire complète (RAM, limité 100 MB)",
            "② Calcul MD5/SHA1/SHA256 via DLL C++ (multithreadé)",
            "③ Détection magic bytes (lecture 16 premiers octets)",
            "④ Scan signatures packers (UPX, Themida, VMProtect…)",
            "⑤ Entropie Shannon C++ multithreadée (chunks 64 KB)",
            "⑥ Extraction strings ASCII + Wide Unicode (C++)",
            "⑦ Matching patterns suspects (Boyer-Moore-Horspool C++)",
            "⑧ Parsing PE complet : sections, entropies, overlay",
            "⑨ Analyse fréquence octets (chi-carré)",
            "⑩ Extraction métadonnées OS (stat + Authenticode PS)",
            "📂 Accès : LECTURE SEULE du fichier cible",
        ],
        "heuristic": [
            "① Scan 30+ patterns ransomware binaires",
            "② Détection APIs injection code (CreateRemoteThread…)",
            "③ Détection anti-debug (IsDebuggerPresent…)",
            "④ Détection anti-VM (VirtualBox, VMware, QEMU…)",
            "⑤ Détection persistence (Run keys, schtasks…)",
            "⑥ Détection élévation privilèges (SeDebugPrivilege…)",
            "⑦ Détection vol credentials (lsass, SAM…)",
            "⑧ Détection obfuscation (base64, hex, URL encoding)",
            "📂 Accès : LECTURE SEULE — AUCUNE exécution",
        ],
        "network": [
            "① Extraction URLs HTTP/HTTPS via regex",
            "② Extraction IPs (filtrage RFC1918)",
            "③ Scan domaines TLDs malveillants (.tk .ml .xyz…)",
            "④ Détection domaines .onion (réseau Tor)",
            "⑤ Détection payloads base64 >120 chars",
            "⑥ Matching patterns C2 (User-Agent, GET/POST…)",
            "📡 AUCUNE connexion réseau — analyse statique uniquement",
        ],
        "system": [
            "① Scan chemins fichiers système sensibles (SAM, ntds…)",
            "② Scan clés registre persistence / démarrage",
            "③ Détection chargement pilote kernel",
            "④ Détection bypass UAC (fodhelper, eventvwr…)",
            "📂 AUCUNE exécution — lecture seule",
        ],
        "iq": [
            "① Cohérence temporelle (créé/modifié/PE timestamp)",
            "② Détection RTLO / homoglyphes / zero-width chars",
            "③ Analyse entropie nom de fichier",
            "④ Vérification extensions multiples",
            "⑤ Anomalies sections PE (EXEC+WRITE, entropy .text)",
            "⑥ Overlay PE haute entropie",
            "⑦ Contradictions métadonnées / contenu réel",
            "⑧ Détection signatures compilateurs suspects",
            "⑨ Analyse densité bytes nuls",
            "⑩ Chi-carré distribution octets",
        ],
        "cloud": [
            "① GET /v3/files/{sha256} (hash lookup VT)",
            "② Si 404 : POST /v3/files (upload ≤32 MB)",
            "③ Polling résultats (max 60s, poll 5s)",
            "④ Extraction score + liste moteurs positifs",
            "⑤ Mise en cache résultat (24h RAM + disque)",
            f"📡 CONNEXION INTERNET requise (api.virustotal.com)",
            f"🔑 Clé API : {'✅ Configurée' if vt_key else '❌ MANQUANTE'}",
        ],
        "sandbox": [
            "① Avertissement utilisateur + confirmation",
            "② Snapshot fichiers système avant exécution",
            "③ Lancement processus via subprocess",
            "④ Monitoring temps réel (psutil, 500ms polling) :",
            "   • Processus enfants créés",
            "   • Fichiers ouverts / créés / modifiés",
            "   • Connexions réseau (psutil.net_connections)",
            "   • Consommation CPU / RAM",
            "   • System calls observables",
            "⑤ Kill du processus après timeout configurable",
            "⑥ Diff snapshot avant/après (fichiers système)",
            "⑦ Rapport comportemental complet",
            "⚠️  EXÉCUTION RÉELLE — environnement non isolé niveau VM",
        ],
    }
    for mid, on in enabled.items():
        if not on or mid not in MODULES: continue
        cfg = MODULES[mid]
        lines.append(f"  [{order}] {cfg['icon']} {cfg['name'].upper()}")
        for line in descriptions.get(mid, []):
            lines.append(f"      {line}")
        lines.append("")
        order += 1

    est = estimate_time(path, enabled)
    lines += ["  ESTIMATION TEMPS","  " + "─"*58,
              f"  Fichiers   : {est['files']}",
              f"  Taille     : {est['size_mb']} MB",
              f"  Durée est. : {est['human']}",""]
    for mid, t in est["breakdown"].items():
        lines.append(f"  {MODULES[mid]['icon']} {MODULES[mid]['name']:<20} {t}s")
    lines += ["","═"*62]
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ════════════════════════════════════════════════════════════

def run_analysis(path: str, enabled: dict, vt_key: str = "",
                 dont_trust: bool = False, cb: Callable = print) -> dict:
    from sandbox import run_sandbox

    results = {
        "path": path, "filename": os.path.basename(path),
        "timestamp": datetime.now().isoformat(),
        "enabled": enabled, "dont_trust": dont_trust,
        "core_cpp": CORE._available,
    }

    # Check cache first (skip if sandbox enabled — always fresh)
    if not enabled.get("sandbox"):
        ck = CacheManager.file_key(path, enabled)
        cached = get_cache().get(ck)
        if cached:
            cb("💾 Résultats depuis le cache…")
            cached["from_cache"] = True
            return cached

    if enabled.get("static"):
        results["static"] = static_analysis(path, cb)

    if enabled.get("heuristic"):
        results["heuristic"] = heuristic_analysis(path, cb)

    if enabled.get("network"):
        results["network"] = network_analysis(path, cb)

    if enabled.get("system"):
        results["system"] = system_analysis(path, cb)

    if enabled.get("iq"):
        results["iq"] = iq_analysis(path, results.get("static",{}), cb)

    if enabled.get("cloud"):
        hashes  = results.get("static",{}).get("hashes",{}) or CORE.compute_hashes(_read(path))
        results["cloud"] = virustotal(path, vt_key, hashes.get("sha256",""), cb)

    if enabled.get("sandbox"):
        results["sandbox"] = run_sandbox(path, cb)

    cb("📊 Calcul du score non-linéaire…")
    results["final"] = final_score(results, enabled, dont_trust)

    # Cache result
    if not enabled.get("sandbox"):
        ck = CacheManager.file_key(path, enabled)
        get_cache().put(ck, results, ttl_h=CACHE_DEFAULTS["ttl_static_h"])

    return results