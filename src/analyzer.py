# ============================================================
#  HARD FILE ANALYZER — analyzer.py
#  Moteur d'analyse : modules statique, heuristique, réseau,
#  système, IQ, cloud (VirusTotal), sandbox
# ============================================================

import hashlib, os, re, math, time, subprocess, json
from datetime import datetime
from collections import Counter
from typing import Callable, Optional
from config import *

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


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

def _read(path: str, max_mb: int = 50) -> bytes:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        return f.read(min(size, max_mb * 1024 * 1024))

def _str(data: bytes) -> str:
    return data.decode("latin-1", errors="replace")


# ════════════════════════════════════════════════════════════
#  1 · STATIC ANALYSIS
# ════════════════════════════════════════════════════════════

def compute_hashes(path: str) -> dict:
    try:
        data = _read(path)
        return {
            "md5":    hashlib.md5(data).hexdigest(),
            "sha1":   hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    except Exception as e:
        return {"error": str(e)}

def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    cnt = Counter(data)
    total = len(data)
    return round(-sum((c/total)*math.log2(c/total) for c in cnt.values()), 4)

def detect_type(path: str) -> dict:
    out = {"type": "Unknown", "magic": "", "packed": False, "packer": ""}
    try:
        with open(path, "rb") as f:
            hdr = f.read(16)
        out["magic"] = hdr.hex()
        for sig, t in MAGIC_SIGS.items():
            if hdr[:len(sig)] == sig:
                out["type"] = t; break
        # Packer detection
        if hdr[:2] == b'\x4d\x5a':
            data = _read(path, 10)
            for p in PACKER_SIGS:
                if p in data:
                    out["packed"] = True
                    out["packer"] = p.decode("latin-1"); break
            if not out["packed"] and shannon_entropy(data[:65536]) > 7.2:
                out["packed"] = True
                out["packer"] = "Unknown packer (high entropy)"
    except Exception as e:
        out["error"] = str(e)
    return out

def ext_mismatch(path: str, detected: str) -> dict:
    ext = os.path.splitext(path)[1].lower()
    expected = EXT_EXPECTED.get(ext, [])
    ok = not expected or any(e.lower() in detected.lower() for e in expected)
    severity = "none"
    if not ok and detected not in ("Unknown",""):
        # Executable hiding as image/doc = critical
        crit_ext = {'.jpg','.jpeg','.png','.gif','.bmp','.txt','.pdf','.docx','.xlsx'}
        severity = "high" if ext in crit_ext and "PE" in detected else "medium"
    return {"extension": ext, "detected": detected, "mismatch": not ok, "severity": severity}

def entropy_sections(path: str) -> dict:
    try:
        data = _read(path)
        overall = shannon_entropy(data)
        suspicious = []
        chunk = 4096
        for i in range(0, min(len(data), 65536), chunk):
            e = shannon_entropy(data[i:i+chunk])
            if e > 7.0:
                suspicious.append({"offset": f"0x{i:08x}", "entropy": e})
        return {"overall": overall, "high_entropy": overall > 7.0, "suspicious_sections": suspicious}
    except Exception as e:
        return {"error": str(e)}

def extract_strings(path: str, min_len: int = 6) -> dict:
    try:
        data = _read(path)
        strings, cur = [], ""
        for b in data:
            c = chr(b)
            if c.isprintable() and c not in "\r\n":
                cur += c
            else:
                if len(cur) >= min_len: strings.append(cur)
                cur = ""
        if len(cur) >= min_len: strings.append(cur)
        suspicious = []
        for s in strings:
            sl = s.lower()
            for pat in SUSPICIOUS_STRINGS:
                if pat.lower() in sl:
                    suspicious.append({"string": s[:120], "pattern": pat}); break
        return {"total": len(strings), "sample": strings[:200], "suspicious": suspicious[:80]}
    except Exception as e:
        return {"error": str(e)}

def extract_metadata(path: str) -> dict:
    try:
        st = os.stat(path)
        meta = {
            "filename":  os.path.basename(path),
            "extension": os.path.splitext(path)[1].lower(),
            "size_bytes": st.st_size,
            "size_human": _human_size(st.st_size),
            "created":   datetime.fromtimestamp(st.st_ctime).isoformat(),
            "modified":  datetime.fromtimestamp(st.st_mtime).isoformat(),
            "accessed":  datetime.fromtimestamp(st.st_atime).isoformat(),
            "signature": "Unknown",
        }
        try:
            r = subprocess.run(
                ["powershell","-Command",f'(Get-AuthenticodeSignature "{path}").Status'],
                capture_output=True, text=True, timeout=5
            )
            meta["signature"] = r.stdout.strip() or "Unknown"
        except: pass
        return meta
    except Exception as e:
        return {"error": str(e)}

def static_analysis(path: str, cb: Callable) -> dict:
    cb("🔬 Calcul des hashes (MD5 / SHA1 / SHA256)…")
    hashes = compute_hashes(path)
    cb("🔬 Détection du type réel via magic bytes…")
    ftype  = detect_type(path)
    cb("🔬 Extraction des métadonnées…")
    meta   = extract_metadata(path)
    cb("🔬 Vérification cohérence extension ↔ contenu…")
    extchk = ext_mismatch(path, ftype["type"])
    cb("🔬 Analyse de l'entropie (détection obfuscation)…")
    ent    = entropy_sections(path)
    cb("🔬 Extraction des strings internes…")
    strs   = extract_strings(path)

    score = 0
    if ent.get("high_entropy"):           score += W["high_entropy"]
    if extchk["severity"] == "high":      score += W["ext_mismatch_high"]
    elif extchk["severity"] == "medium":  score += W["ext_mismatch_med"]
    if ftype.get("packed"):               score += W["packed"]
    n_sus = len(strs.get("suspicious", []))
    if n_sus > 20:   score += W["suspicious_str_many"]
    elif n_sus > 5:  score += W["suspicious_str_few"]

    return {"hashes": hashes, "type": ftype, "metadata": meta,
            "ext_check": extchk, "entropy": ent, "strings": strs,
            "score": min(score, 100)}


# ════════════════════════════════════════════════════════════
#  2 · HEURISTIC ANALYSIS
# ════════════════════════════════════════════════════════════

def heuristic_analysis(path: str, cb: Callable) -> dict:
    cb("🧠 Scan patterns ransomware…")
    result = {
        "ransomware": [], "injection": [], "anti_debug": [],
        "anti_vm": [], "persistence": [], "privesc": [],
        "obfuscation": False, "score": 0,
    }
    try:
        data = _read(path)
        ds   = _str(data)

        for pat in RANSOMWARE_BYTES:
            if pat in data:
                result["ransomware"].append(pat.decode("latin-1"))

        cb("🧠 Détection injection de code…")
        for api in ["VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
                    "NtCreateThreadEx","RtlCreateUserThread","SetWindowsHookEx",
                    "QueueUserAPC","NtQueueApcThread","MapViewOfFile2"]:
            if api.encode() in data or api in ds:
                result["injection"].append(api)

        cb("🧠 Détection anti-analyse / anti-debug…")
        for api in ["IsDebuggerPresent","CheckRemoteDebuggerPresent",
                    "NtQueryInformationProcess","OutputDebugString",
                    "GetTickCount","QueryPerformanceCounter"]:
            if api.encode() in data or api in ds:
                result["anti_debug"].append(api)

        for vm in ["VBOX","VMWARE","VirtualBox","vboxservice","vmtoolsd",
                   "wine_get_unix_file_name","QEMU","BOCHS","Hyper-V"]:
            if vm.encode() in data or vm in ds:
                result["anti_vm"].append(vm)

        cb("🧠 Détection persistence / startup…")
        for p in ["CurrentVersion\\Run","CurrentVersion\\RunOnce",
                  "Winlogon\\Shell","Winlogon\\Userinit","\\Startup\\",
                  "schtasks","SCHTASKS","at.exe","SC CREATE"]:
            if p in ds: result["persistence"].append(p)

        cb("🧠 Détection élévation de privilèges…")
        for p in ["SeDebugPrivilege","SeTcbPrivilege","AdjustTokenPrivileges",
                  "ImpersonateLoggedOnUser","CreateProcessWithTokenW",
                  "TokenImpersonation","runas","bypassuac"]:
            if p.encode() in data or p.lower() in ds.lower():
                result["privesc"].append(p)

        cb("🧠 Détection obfuscation / encodage…")
        if re.search(rb'[A-Za-z0-9+/]{80,}={0,2}', data):
            result["obfuscation"] = True
        if re.search(r'(\\x[0-9a-fA-F]{2}){10,}', ds):
            result["obfuscation"] = True

        s = 0
        if result["ransomware"]:     s += W["ransomware"]
        if result["injection"]:      s += W["code_injection"]
        if result["anti_debug"]:     s += W["anti_debug"]
        if result["anti_vm"]:        s += W["anti_vm"]
        if result["persistence"]:    s += W["persistence"]
        if result["privesc"]:        s += W["privesc"]
        if result["obfuscation"]:    s += W["obfuscation"]
        result["score"] = min(s, 100)

    except Exception as e:
        result["error"] = str(e)
    return result


# ════════════════════════════════════════════════════════════
#  3 · NETWORK ANALYSIS (static)
# ════════════════════════════════════════════════════════════

def network_analysis(path: str, cb: Callable) -> dict:
    cb("🌐 Extraction des URLs et IPs…")
    result = {"urls": [], "ips": [], "domains_suspicious": [],
              "base64_payloads": [], "score": 0}
    try:
        data = _read(path)
        ds   = _str(data)

        result["urls"] = list(set(
            re.findall(r'https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]{5,}', ds)
        ))[:60]

        all_ips = re.findall(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b', ds
        )
        result["ips"] = list(set(
            ip for ip in all_ips
            if not re.match(r'^(127\.|0\.0\.0\.|255\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)', ip)
        ))[:40]

        cb("🌐 Détection domaines suspects / TLDs malveillants…")
        domains = re.findall(r'[a-zA-Z0-9\-]{3,63}\.[a-zA-Z]{2,}', ds)
        for d in set(domains):
            for tld in SUSPICIOUS_TLDS:
                if d.lower().endswith(tld):
                    result["domains_suspicious"].append(d); break
        result["domains_suspicious"] = result["domains_suspicious"][:30]

        cb("🌐 Détection payloads base64 encodés…")
        b64 = re.findall(rb'[A-Za-z0-9+/]{100,}={0,2}', data)
        result["base64_payloads"] = [m.decode("ascii","replace")[:80] for m in b64[:10]]

        s = 0
        if result["ips"]:                  s += W["ip_external"]
        if result["domains_suspicious"]:   s += W["suspicious_domain"]
        if result["base64_payloads"]:      s += W["c2_patterns"]
        result["score"] = min(s, 100)

    except Exception as e:
        result["error"] = str(e)
    return result


# ════════════════════════════════════════════════════════════
#  4 · SYSTEM ANALYSIS (theoretical)
# ════════════════════════════════════════════════════════════

def system_analysis(path: str, cb: Callable) -> dict:
    cb("⚙️ Analyse accès fichiers système sensibles…")
    result = {
        "sensitive_files": [], "registry_keys": [],
        "privilege_req": False, "startup": False,
        "driver_load": False, "score": 0,
    }
    try:
        data = _read(path)
        ds   = _str(data)

        for f in ["\\SAM","\\SYSTEM","\\SECURITY","\\ntds.dit","\\lsass.exe",
                  "\\winlogon.exe","\\services.exe","\\drivers\\etc\\hosts",
                  "\\System32\\config\\","\\shadow","ntlm"]:
            if f in ds: result["sensitive_files"].append(f)

        cb("⚙️ Analyse modifications registre…")
        for k in ["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                  "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                  "HKLM\\SYSTEM\\CurrentControlSet\\Services",
                  "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                  "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]:
            if k in ds or k.replace("\\","\\\\") in ds:
                result["registry_keys"].append(k)

        cb("⚙️ Vérification élévation de privilèges / drivers…")
        if any(p in ds for p in ["SeDebugPrivilege","CreateService","OpenSCManager","runas"]):
            result["privilege_req"] = True
        if any(p in ds for p in ["\\Startup\\","CurrentVersion\\Run","Winlogon"]):
            result["startup"] = True
        if any(p in ds for p in ["NtLoadDriver","ZwLoadDriver","\\drivers\\",".sys\x00"]):
            result["driver_load"] = True

        s = 0
        if result["sensitive_files"]:  s += W["sensitive_files"]
        if result["registry_keys"]:    s += W["persistence"]
        if result["privilege_req"]:    s += W["privesc"]
        if result["startup"]:          s += W["persistence"]
        if result["driver_load"]:      s += W["driver_load"]
        result["score"] = min(s, 100)

    except Exception as e:
        result["error"] = str(e)
    return result


# ════════════════════════════════════════════════════════════
#  5 · IQ MODE — Logical Inconsistencies
# ════════════════════════════════════════════════════════════

def iq_analysis(path: str, meta: dict, ftype: dict, cb: Callable) -> dict:
    cb("🧩 IQ — Analyse cohérence temporelle…")
    result = {
        "temporal": [], "structure": [], "metadata_contra": [],
        "logical": [], "score": 0,
    }
    try:
        now = datetime.now()
        created  = datetime.fromisoformat(meta.get("created","2000-01-01"))
        modified = datetime.fromisoformat(meta.get("modified","2000-01-01"))

        if modified < created:
            result["temporal"].append("⚠️ Modification antérieure à la création (timestamp manipulé)")
        if created > now:
            result["temporal"].append(f"⚠️ Date de création dans le futur ({created.date()})")
        if modified > now:
            result["temporal"].append(f"⚠️ Date de modification dans le futur ({modified.date()})")
        if created.year < 1985:
            result["temporal"].append(f"⚠️ Date anormalement ancienne : {created.year}")

        cb("🧩 IQ — Analyse structure / extensions…")
        data = _read(path)
        name = os.path.basename(path)
        parts = name.split(".")
        if len(parts) > 2:
            result["structure"].append(f"⚠️ Extensions multiples : {name}")
        if len(data) == 0:
            result["structure"].append("⚠️ Fichier vide (0 octets)")
        ext = meta.get("extension","")
        min_sizes = {'.exe':1024,'.dll':1024,'.pdf':100,'.docx':500,'.zip':22}
        if ext in min_sizes and len(data) < min_sizes[ext]:
            result["structure"].append(
                f"⚠️ Fichier trop petit pour {ext} ({len(data)} octets)")
        if data[:16] == b'\x00'*16 and len(data) > 16:
            result["structure"].append("⚠️ Entête nulle (manipulation de signature possible)")

        # Overlay data after PE
        if "PE" in ftype.get("type","") and len(data) > 4096:
            tail_ent = shannon_entropy(data[-4096:])
            if tail_ent > 7.5:
                result["structure"].append(
                    f"⚠️ Données chiffrées/packées en fin de fichier (entropie {tail_ent:.2f})")

        cb("🧩 IQ — Contradictions métadonnées / contenu…")
        sig = meta.get("signature","Unknown")
        if sig == "Valid" and ftype.get("packed"):
            result["metadata_contra"].append(
                "⚠️ Fichier signé numériquement mais packer détecté")
        # High entropy but small file declared as document
        if ftype.get("type","") == "PDF" and len(data) > 0:
            ent = shannon_entropy(data)
            if ent > 7.5:
                result["metadata_contra"].append(
                    f"⚠️ PDF avec entropie suspecte ({ent:.2f}) — possible stéganographie")

        cb("🧩 IQ — Anomalies logiques globales…")
        size = meta.get("size_bytes",0)
        if size > 50*1024*1024:
            n_str = len(re.findall(rb'[A-Za-z0-9]{6,}', data[:65536]))
            if n_str < 20:
                result["logical"].append(
                    "⚠️ Fichier volumineux avec très peu de strings (chiffrement probable)")
        # Script extension but PE binary inside
        if ext in {'.js','.py','.vbs','.bat','.ps1'} and b'\x4d\x5a' in data[:4]:
            result["logical"].append(
                f"⚠️ Extension script ({ext}) mais signature PE Executable détectée en-tête")

        s  = len(result["temporal"])      * W["iq_temporal"]
        s += len(result["structure"])     * W["iq_structure"]
        s += len(result["metadata_contra"])* W["iq_metadata"]
        s += len(result["logical"])       * W["iq_logical"]
        result["score"] = min(s, 100)

    except Exception as e:
        result["error"] = str(e)
    return result


# ════════════════════════════════════════════════════════════
#  6 · CLOUD — VirusTotal
# ════════════════════════════════════════════════════════════

def virustotal(path: str, api_key: str, hashes: dict, cb: Callable) -> dict:
    result = {
        "checked": False, "found": False, "detections": 0,
        "total": 0, "rate": "0%", "permalink": "",
        "engines": {}, "score": 0,
    }
    if not HAS_REQUESTS:
        result["error"] = "Module 'requests' manquant (pip install requests)"
        return result
    if not api_key:
        result["error"] = "Clé API VirusTotal non configurée"
        return result

    headers = {"x-apikey": api_key}
    sha = hashes.get("sha256","")

    try:
        cb("☁️ Vérification hash SHA256 sur VirusTotal…")
        r = requests.get(f"{VIRUSTOTAL_API}/files/{sha}", headers=headers, timeout=12)

        if r.status_code == 200:
            attrs = r.json().get("data",{}).get("attributes",{})
            stats = attrs.get("last_analysis_stats",{})
            result["checked"] = result["found"] = True
            result["detections"] = stats.get("malicious",0) + stats.get("suspicious",0)
            result["total"]      = sum(stats.values())
            result["permalink"]  = f"https://www.virustotal.com/gui/file/{sha}"
            if result["total"]:
                result["rate"] = f"{result['detections']/result['total']*100:.1f}%"
            engines = attrs.get("last_analysis_results",{})
            result["engines"] = {
                k: v.get("result","") for k,v in engines.items()
                if v.get("category") in ("malicious","suspicious")
            }

        elif r.status_code == 404:
            fsize = os.path.getsize(path)
            if fsize > 32*1024*1024:
                result["error"] = "Fichier >32 MB — upload VirusTotal non possible"
                return result
            cb("☁️ Hash inconnu — upload du fichier sur VirusTotal…")
            with open(path,"rb") as f:
                up = requests.post(f"{VIRUSTOTAL_API}/files",
                                   headers=headers, files={"file":f}, timeout=90)
            if up.status_code == 200:
                aid = up.json().get("data",{}).get("id","")
                result["checked"] = True
                result["permalink"] = f"https://www.virustotal.com/gui/file-analysis/{aid}"
                cb("☁️ Analyse en cours — attente des résultats…")
                for _ in range(12):
                    time.sleep(5)
                    poll = requests.get(f"{VIRUSTOTAL_API}/analyses/{aid}",
                                        headers=headers, timeout=12)
                    if poll.status_code == 200:
                        pdata = poll.json().get("data",{}).get("attributes",{})
                        if pdata.get("status") == "completed":
                            st = pdata.get("stats",{})
                            result["detections"] = st.get("malicious",0)+st.get("suspicious",0)
                            result["total"]      = sum(st.values())
                            if result["total"]:
                                result["rate"] = f"{result['detections']/result['total']*100:.1f}%"
                            break
        else:
            result["error"] = f"API VirusTotal : HTTP {r.status_code}"

        d,t = result["detections"], result["total"]
        if t and d:
            pct = d/t
            if pct < 0.10: result["score"] = W["vt_low"]
            elif pct < 0.30: result["score"] = W["vt_medium"]
            else:            result["score"] = W["vt_high"]

    except Exception as e:
        result["error"] = f"Erreur réseau : {e}"
    return result


# ════════════════════════════════════════════════════════════
#  7 · SANDBOX (static simulation)
# ════════════════════════════════════════════════════════════

def sandbox_analysis(path: str, cb: Callable) -> dict:
    result = {
        "simulated": True,
        "executable": False,
        "api_calls": [],
        "files_expected": [],
        "network_expected": [],
        "registry_expected": [],
        "anti_vm": False,
        "score": 0,
        "note": "Simulation statique — exécution réelle nécessite environnement dédié (Cuckoo / Windows Sandbox)"
    }
    ext = os.path.splitext(path)[1].lower()
    if ext not in {'.exe','.dll','.bat','.cmd','.ps1','.vbs','.js','.msi'}:
        result["note"] = f"Non-exécutable ({ext}) — sandbox ignorée"
        return result

    result["executable"] = True
    cb("📦 Sandbox — prédiction des API calls…")
    try:
        data = _read(path)
        ds   = _str(data)

        api_map = {
            "CreateProcess":       "Création processus enfant",
            "CreateFile":          "Accès fichier système",
            "RegSetValueEx":       "Modification registre",
            "InternetConnect":     "Connexion réseau sortante",
            "socket":              "Création socket TCP/UDP",
            "VirtualAllocEx":      "Allocation mémoire distante (injection)",
            "WriteProcessMemory":  "Écriture mémoire processus (injection)",
            "ShellExecuteEx":      "Exécution via shell",
            "WinHttpConnect":      "Requête HTTP(S) sortante",
            "CryptEncrypt":        "Chiffrement (possible ransomware)",
            "DeleteFile":          "Suppression de fichiers",
            "FindFirstFile":       "Énumération fichiers (possible chiffrement de masse)",
        }
        for api, desc in api_map.items():
            if api.encode() in data or api in ds:
                result["api_calls"].append({"api": api, "description": desc})

        cb("📦 Sandbox — prédiction effets système…")
        for p in ["\\Startup\\","\\System32\\","\\Temp\\","\\AppData\\Roaming\\"]:
            if p in ds:
                result["files_expected"].append(p + "… (create/modify suspected)")

        ip_patt = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
        for ip in set(ip_patt.findall(ds)):
            if not re.match(r'^(127\.|0\.0\.0\.|255\.)',ip):
                result["network_expected"].append({"ip":ip, "type":"C2 suspect"})
        result["network_expected"] = result["network_expected"][:15]

        for k in ["CurrentVersion\\Run","SYSTEM\\CurrentControlSet\\Services"]:
            if k in ds: result["registry_expected"].append(k)

        cb("📦 Sandbox — détection anti-VM / anti-debug…")
        for vm in ["VBOX","VMWARE","VirtualBox","vboxservice","vmtoolsd",
                   "IsDebuggerPresent","QEMU","wine_get_unix"]:
            if vm.encode() in data or vm in ds:
                result["anti_vm"] = True; break

        s = 0
        if result["api_calls"]:         s += W["sandbox_suspicious_api"] * min(len(result["api_calls"]),5)
        if result["anti_vm"]:           s += W["sandbox_anti_vm"]
        if result["network_expected"]:  s += W["sandbox_network"]
        result["score"] = min(s, 100)

    except Exception as e:
        result["error"] = str(e)
    return result


# ════════════════════════════════════════════════════════════
#  SCORE FINAL
# ════════════════════════════════════════════════════════════

def final_score(results: dict, enabled: dict, dont_trust: bool) -> dict:
    scores, factors = [], []

    def add(key, score_key, label_fn=None):
        if enabled.get(key) and key in results:
            s = results[key].get("score", 0)
            scores.append(s)
            if label_fn: label_fn(results[key], factors)

    def static_labels(r, f):
        if r.get("entropy",{}).get("high_entropy"):    f.append("Haute entropie détectée")
        if r.get("ext_check",{}).get("mismatch"):      f.append("Extension ↔ contenu : MISMATCH")
        if r.get("type",{}).get("packed"):             f.append(f"Packer : {r['type'].get('packer','?')}")
        n = len(r.get("strings",{}).get("suspicious",[]))
        if n: f.append(f"{n} strings suspects")

    def heur_labels(r, f):
        if r.get("ransomware"):   f.append(f"Ransomware patterns ({len(r['ransomware'])})")
        if r.get("injection"):    f.append(f"Code injection APIs ({len(r['injection'])})")
        if r.get("anti_vm"):      f.append(f"Anti-VM ({', '.join(r['anti_vm'][:2])})")
        if r.get("anti_debug"):   f.append(f"Anti-debug ({', '.join(r['anti_debug'][:2])})")
        if r.get("persistence"):  f.append("Persistence / startup détecté")
        if r.get("privesc"):      f.append("Élévation de privilèges")

    def net_labels(r, f):
        if r.get("ips"):                f.append(f"{len(r['ips'])} IPs externes")
        if r.get("domains_suspicious"): f.append(f"{len(r['domains_suspicious'])} domaines suspects")
        if r.get("base64_payloads"):    f.append(f"{len(r['base64_payloads'])} payloads base64")

    def iq_labels(r, f):
        all_a = r.get("temporal",[]) + r.get("structure",[]) + r.get("metadata_contra",[]) + r.get("logical",[])
        if all_a: f.append(f"IQ : {len(all_a)} anomalies logiques")

    def cloud_labels(r, f):
        if r.get("detections",0): f.append(f"VirusTotal : {r['detections']}/{r['total']} moteurs")

    add("static",    "score", static_labels)
    add("heuristic", "score", heur_labels)
    add("network",   "score", net_labels)
    add("system",    "score")
    add("iq",        "score", iq_labels)
    add("cloud",     "score", cloud_labels)
    add("sandbox",   "score")

    if scores:
        scores_s = sorted(scores, reverse=True)
        val = scores_s[0]
        for i, s in enumerate(scores_s[1:], 1):
            val = val * 0.65 + s * 0.35 * (0.85**i)
        final = min(int(val), 100)
    else:
        final = 0

    label, color, icon = get_risk(final)
    return {
        "score": final, "label": label, "color": color, "icon": icon,
        "factors": factors, "dont_trust": dont_trust,
    }


# ════════════════════════════════════════════════════════════
#  TIME ESTIMATION
# ════════════════════════════════════════════════════════════

def estimate_time(path: str, enabled: dict) -> dict:
    total_mb, count = 0.0, 0
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in files:
                fp = os.path.join(root, f)
                try: total_mb += os.path.getsize(fp)/1048576; count += 1
                except: pass
    else:
        try: total_mb = os.path.getsize(path)/1048576; count = 1
        except: pass

    total_mb = max(total_mb, 0.01)
    breakdown, total_s = {}, 0.0
    for mid, on in enabled.items():
        if on and mid in MODULES:
            t = max(MODULES[mid]["tpm"] * total_mb * max(count,1), 0.5)
            breakdown[mid] = round(t, 1)
            total_s += t

    return {
        "seconds": round(total_s, 1),
        "human":   _fmt_time(total_s),
        "files":   count,
        "size_mb": round(total_mb, 2),
        "breakdown": breakdown,
    }


# ════════════════════════════════════════════════════════════
#  TRACKING MODE — pre-scan report
# ════════════════════════════════════════════════════════════

def tracking_report(path: str, enabled: dict, vt_key: str) -> str:
    lines = [
        "═" * 60,
        "  🔍 MODE TRACKING — RAPPORT PRÉ-ANALYSE",
        "═" * 60,
        f"  Cible     : {path}",
        f"  Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "  MODULES ACTIVÉS ET ACTIONS PRÉVUES",
        "  " + "─" * 56,
    ]
    order = 1
    if enabled.get("static"):
        lines += [
            f"  [{order}] 🔬 ANALYSE STATIQUE",
            "      ① Lecture binaire complète du fichier",
            "      ② Calcul MD5, SHA1, SHA256",
            "      ③ Lecture magic bytes (16 premiers octets)",
            "      ④ Extraction métadonnées OS (stat())",
            "      ⑤ Vérification signature numérique (PowerShell)",
            "      ⑥ Calcul entropie Shannon (chunks 4KB)",
            "      ⑦ Extraction strings ASCII/Unicode (min 6 chars)",
            "      ⑧ Matching signatures packer (UPX, Themida…)",
            "      📂 Fichiers utilisés : le fichier cible uniquement",
            "",
        ]; order += 1
    if enabled.get("heuristic"):
        lines += [
            f"  [{order}] 🧠 ANALYSE HEURISTIQUE",
            "      ① Scan patterns ransomware (30+ signatures)",
            "      ② Détection APIs d'injection (WriteProcessMemory…)",
            "      ③ Détection anti-debug (IsDebuggerPresent…)",
            "      ④ Détection anti-VM (VMWARE, VBOX, VirtualBox…)",
            "      ⑤ Détection persistence (Run keys, schtasks…)",
            "      ⑥ Détection élévation privilèges (SeDebugPrivilege…)",
            "      ⑦ Détection obfuscation base64 / hex",
            "      📂 Fichiers utilisés : lecture seule du fichier cible",
            "",
        ]; order += 1
    if enabled.get("network"):
        lines += [
            f"  [{order}] 🌐 ANALYSE RÉSEAU STATIQUE",
            "      ① Extraction URLs (regex HTTP/HTTPS)",
            "      ② Extraction adresses IP (filtrage RFC1918)",
            "      ③ Scan domaines TLDs malveillants (.tk .ml .xyz…)",
            "      ④ Détection payloads base64 (>100 chars)",
            "      📂 Aucune connexion réseau — analyse statique uniquement",
            "",
        ]; order += 1
    if enabled.get("system"):
        lines += [
            f"  [{order}] ⚙️ ANALYSE SYSTÈME (THÉORIQUE)",
            "      ① Scan chemins fichiers sensibles (SAM, ntds.dit…)",
            "      ② Scan clés registre de persistence",
            "      ③ Détection chargement de pilote kernel",
            "      ④ Analyse élévation de privilèges",
            "      📂 Aucune exécution — lecture seule du binaire",
            "",
        ]; order += 1
    if enabled.get("iq"):
        lines += [
            f"  [{order}] 🧩 MODE IQ",
            "      ① Comparaison timestamps créé/modifié",
            "      ② Détection dates futures ou impossibles",
            "      ③ Analyse extensions multiples",
            "      ④ Vérification taille minimale par type",
            "      ⑤ Détection données de fin de fichier suspectes",
            "      ⑥ Contradictions métadonnées / contenu",
            "      📂 Aucune exécution — analyse logique uniquement",
            "",
        ]; order += 1
    if enabled.get("cloud"):
        vt_status = "✅ Clé configurée" if vt_key else "❌ Clé MANQUANTE"
        lines += [
            f"  [{order}] ☁️ CLOUD VIRUSTOTAL  ({vt_status})",
            "      ① Requête GET /files/{sha256} (hash lookup)",
            "      ② Si inconnu : upload POST /files (≤32 MB)",
            "      ③ Polling résultats (max 60 secondes)",
            "      ④ Extraction score multi-AV et moteurs positifs",
            "      📡 CONNEXION INTERNET REQUISE vers api.virustotal.com",
            "",
        ]; order += 1
    if enabled.get("sandbox"):
        lines += [
            f"  [{order}] 📦 SANDBOX (SIMULATION STATIQUE)",
            "      ① Prédiction API calls depuis analyse binaire",
            "      ② Prédiction effets fichiers système",
            "      ③ Prédiction connexions réseau",
            "      ④ Détection anti-VM / anti-sandbox statique",
            "      ⚠️  Aucune exécution réelle — simulation comportementale",
            "      📂 Lecture seule du fichier cible",
            "",
        ]; order += 1

    est = estimate_time(path, enabled)
    lines += [
        "  ESTIMATION TEMPS",
        "  " + "─" * 56,
        f"  Fichiers   : {est['files']}",
        f"  Taille     : {est['size_mb']} MB",
        f"  Durée est. : {est['human']}",
        "",
    ]
    for mid, t in est["breakdown"].items():
        lines.append(f"  {MODULES[mid]['icon']} {MODULES[mid]['name']:<18} {t}s")
    lines += ["", "═" * 60]
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ════════════════════════════════════════════════════════════

def run_analysis(path: str, enabled: dict, vt_key: str = "",
                 dont_trust: bool = False, cb: Callable = print) -> dict:

    results = {
        "path": path, "filename": os.path.basename(path),
        "timestamp": datetime.now().isoformat(),
        "enabled": enabled, "dont_trust": dont_trust,
    }

    if enabled.get("static"):
        results["static"] = static_analysis(path, cb)

    if enabled.get("heuristic"):
        results["heuristic"] = heuristic_analysis(path, cb)

    if enabled.get("network"):
        results["network"] = network_analysis(path, cb)

    if enabled.get("system"):
        results["system"] = system_analysis(path, cb)

    if enabled.get("iq"):
        meta  = results.get("static",{}).get("metadata",{})
        ftype = results.get("static",{}).get("type",{})
        results["iq"] = iq_analysis(path, meta, ftype, cb)

    if enabled.get("cloud"):
        hashes = results.get("static",{}).get("hashes",{}) or compute_hashes(path)
        results["cloud"] = virustotal(path, vt_key, hashes, cb)

    if enabled.get("sandbox"):
        results["sandbox"] = sandbox_analysis(path, cb)

    cb("📊 Calcul du score de risque final…")
    results["final"] = final_score(results, enabled, dont_trust)
    return results