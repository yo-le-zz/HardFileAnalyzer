# ============================================================
#  HARD FILE ANALYZER — sandbox.py
#  Sandbox réelle : exécution subprocess + monitoring psutil
#  Pas d'API Windows directe — utilise psutil, watchdog, diff
# ============================================================

import os, sys, time, json, threading, subprocess, tempfile, shutil
import hashlib, re, signal
from datetime import datetime
from typing import Callable, Optional, List, Dict, Any

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from config import SANDBOX_DEFAULTS, EXECUTABLE_EXTS, C

# ════════════════════════════════════════════════════════════
#  FILESYSTEM SNAPSHOT
# ════════════════════════════════════════════════════════════

def _expand(path: str) -> str:
    return os.path.expandvars(path)

def _snapshot_dir(directory: str, max_files: int = 5000) -> dict:
    """Capture état d'un répertoire : {chemin: (taille, mtime)}"""
    snap = {}
    try:
        for root, dirs, files in os.walk(directory):
            # Skip very deep paths
            depth = root.replace(directory,"").count(os.sep)
            if depth > 4: dirs.clear(); continue
            for fname in files:
                fp = os.path.join(root, fname)
                try:
                    st = os.stat(fp)
                    snap[fp] = (st.st_size, round(st.st_mtime, 2))
                except: pass
                if len(snap) >= max_files: return snap
    except: pass
    return snap

def _diff_snapshots(before: dict, after: dict) -> dict:
    created  = {k: v for k, v in after.items()  if k not in before}
    deleted  = {k: v for k, v in before.items() if k not in after}
    modified = {
        k: {"before": before[k], "after": after[k]}
        for k in before if k in after and before[k] != after[k]
    }
    return {"created": list(created.keys())[:50],
            "deleted":  list(deleted.keys())[:50],
            "modified": list(modified.keys())[:50]}


# ════════════════════════════════════════════════════════════
#  PROCESS MONITOR
# ════════════════════════════════════════════════════════════

class ProcessMonitor:
    """
    Surveille un processus et ses enfants via psutil.
    Enregistre : enfants, fichiers ouverts, connexions réseau,
    CPU/RAM, DLLs chargées, arguments de ligne de commande.
    """

    def __init__(self, pid: int, poll_ms: int = 500):
        self.pid      = pid
        self.poll_ms  = poll_ms
        self._stop    = threading.Event()
        self._lock    = threading.Lock()
        self.data: Dict[str, Any] = {
            "child_procs":   [],
            "files_opened":  set(),
            "net_conns":     [],
            "dlls_loaded":   set(),
            "cpu_samples":   [],
            "mem_samples":   [],
            "cmdlines":      [],
            "suspicious_apis":[],
            "total_writes":  0,
        }
        self._known_pids = {pid}
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=3)

    def _run(self):
        try:
            root_proc = psutil.Process(self.pid)
        except: return

        while not self._stop.is_set():
            try:
                procs_to_scan = [root_proc] + root_proc.children(recursive=True)
            except: break

            for p in procs_to_scan:
                try:
                    pid = p.pid
                    # New child process discovered
                    if pid not in self._known_pids:
                        self._known_pids.add(pid)
                        try:
                            info = {
                                "pid":     pid,
                                "name":    p.name(),
                                "cmdline": " ".join(p.cmdline()),
                                "exe":     p.exe(),
                                "t":       datetime.now().strftime("%H:%M:%S.%f")[:-3],
                            }
                        except:
                            info = {"pid": pid, "name":"?","cmdline":"?","exe":"?","t":"?"}
                        with self._lock:
                            self.data["child_procs"].append(info)
                            if len(self.data["child_procs"]) > SANDBOX_DEFAULTS["max_child_procs"]:
                                break

                    # Files opened
                    try:
                        for f in p.open_files():
                            with self._lock:
                                self.data["files_opened"].add(f.path)
                    except: pass

                    # Network connections
                    try:
                        for conn in p.connections(kind="all"):
                            if conn.raddr:
                                entry = {
                                    "proto": conn.type.name if hasattr(conn.type,'name') else str(conn.type),
                                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                                    "status": str(conn.status),
                                    "pid": pid,
                                }
                                with self._lock:
                                    if entry not in self.data["net_conns"]:
                                        self.data["net_conns"].append(entry)
                    except: pass

                    # CPU / Memory
                    try:
                        with self._lock:
                            self.data["cpu_samples"].append(p.cpu_percent())
                            self.data["mem_samples"].append(p.memory_info().rss // 1024)
                    except: pass

                    # Loaded DLLs (Windows)
                    try:
                        for m in p.memory_maps():
                            path = getattr(m, 'path', '') or ''
                            if path.lower().endswith('.dll'):
                                with self._lock:
                                    self.data["dlls_loaded"].add(path)
                    except: pass

                    # Cmdlines of all spawned processes
                    try:
                        cl = " ".join(p.cmdline())
                        if cl and cl not in self.data["cmdlines"]:
                            with self._lock:
                                self.data["cmdlines"].append(cl)
                    except: pass

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            self._stop.wait(timeout=self.poll_ms / 1000.0)

    def get_results(self) -> dict:
        with self._lock:
            r = dict(self.data)
            r["files_opened"] = sorted(r["files_opened"])[:200]
            r["dlls_loaded"]  = sorted(r["dlls_loaded"])[:100]
        return r


# ════════════════════════════════════════════════════════════
#  GLOBAL NETWORK SNAPSHOT
# ════════════════════════════════════════════════════════════

def _net_snapshot() -> set:
    if not HAS_PSUTIL: return set()
    try:
        conns = psutil.net_connections(kind="all")
        return {(c.raddr.ip, c.raddr.port) for c in conns if c.raddr}
    except: return set()

def _net_diff(before: set, after: set) -> list:
    return [{"ip": ip, "port": port} for ip, port in after - before]


# ════════════════════════════════════════════════════════════
#  SCORING — Sandbox results
# ════════════════════════════════════════════════════════════

def _score_sandbox(data: dict) -> tuple:
    findings = []
    score    = 0

    n_children = len(data.get("child_procs",[]))
    if n_children > 0:
        score += min(n_children * 8, 30)
        findings.append((f"{n_children} processus enfants créés","HIGH"))

    net = data.get("net_conns",[])
    if net:
        score += min(len(net) * 10, 30)
        findings.append((f"{len(net)} connexions réseau sortantes","HIGH"))
        for conn in net:
            ip = conn.get("raddr","")
            # Non-private IP = suspicious
            if ip and not re.match(r'^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)',ip):
                score += 10; break

    new_files = data.get("new_files",[])
    if new_files:
        score += min(len(new_files)*3, 20)
        # Check if dropping in system paths
        system_paths = ["system32","syswow64","startup","roaming","appdata"]
        for f in new_files:
            if any(sp in f.lower() for sp in system_paths):
                score += 15
                findings.append(("Fichier créé dans chemin système","CRITICAL"))
                break

    mod_files = data.get("modified_files",[])
    if mod_files:
        score += min(len(mod_files)*3, 15)
        findings.append((f"{len(mod_files)} fichiers modifiés","MEDIUM"))

    dlls = data.get("dlls_loaded",[])
    suspicious_dlls = [d for d in dlls if any(
        s in d.lower() for s in ["inject","hook","spy","keylog","debug","sandbox"])]
    if suspicious_dlls:
        score += 20; findings.append(("DLLs suspectes chargées","HIGH"))

    # Anti-VM in observed behavior
    for cmd in data.get("cmdlines",[]):
        if any(x in cmd.lower() for x in ["vbox","vmware","sandbox","debug","wireshark"]):
            score += 15; findings.append(("Comportement anti-VM observé","HIGH")); break

    return min(score, 100), findings


# ════════════════════════════════════════════════════════════
#  MAIN SANDBOX RUNNER
# ════════════════════════════════════════════════════════════

def run_sandbox(path: str, cb: Callable,
                timeout_s: int = None,
                watch_dirs: list = None,
                poll_ms: int = None) -> dict:

    result = {
        "executed":    False,
        "executable":  False,
        "error":       None,
        "child_procs": [],
        "files_opened":[],
        "new_files":   [],
        "deleted_files":[],
        "modified_files":[],
        "net_conns":   [],
        "dlls_loaded": [],
        "cpu_peak":    0.0,
        "mem_peak_kb": 0,
        "cmdlines":    [],
        "exit_code":   None,
        "duration_s":  0.0,
        "new_net_conns":[],
        "findings":    [],
        "score":       0,
    }

    if not HAS_PSUTIL:
        result["error"] = "Module 'psutil' requis (pip install psutil)"
        return result

    ext = os.path.splitext(path)[1].lower()
    if ext not in EXECUTABLE_EXTS:
        result["error"] = f"Extension {ext} non exécutable — sandbox ignorée"
        return result

    result["executable"] = True

    # Defaults
    timeout_s = timeout_s or SANDBOX_DEFAULTS["timeout_s"]
    poll_ms   = poll_ms   or SANDBOX_DEFAULTS["poll_interval_ms"]
    watch_dirs = watch_dirs or [_expand(d) for d in SANDBOX_DEFAULTS["watch_dirs"]]
    watch_dirs = [d for d in watch_dirs if os.path.isdir(d)]

    # ── 1. Snapshot avant ─────────────────────────────────
    cb("📦 Sandbox — Snapshot filesystem avant exécution…")
    snapshots_before = {}
    for d in watch_dirs:
        cb(f"📦 Sandbox — Snapshot : {d}")
        snapshots_before[d] = _snapshot_dir(d)

    net_before = _net_snapshot()

    # ── 2. Lancement processus ────────────────────────────
    cb(f"📦 Sandbox — Lancement du processus (timeout: {timeout_s}s)…")
    proc    = None
    monitor = None
    start_t = time.time()

    try:
        # Launch process with reduced environment
        env = {k: v for k, v in os.environ.items()
               if k in {"PATH","SYSTEMROOT","WINDIR","TEMP","TMP","USERNAME","USERPROFILE",
                         "APPDATA","LOCALAPPDATA","PROGRAMFILES","COMMONPROGRAMFILES"}}

        proc = subprocess.Popen(
            [path] if ext not in {'.bat','.cmd','.ps1','.vbs','.js'} else _get_launcher(path, ext),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x00000008 | 0x00000200,  # DETACHED | CREATE_NEW_PROCESS_GROUP
        )
        result["executed"] = True
        cb(f"📦 Sandbox — PID {proc.pid} — Monitoring en cours ({timeout_s}s)…")

        # ── 3. Start monitor ─────────────────────────────
        monitor = ProcessMonitor(proc.pid, poll_ms=poll_ms)
        monitor.start()

        # Wait with timeout + periodic status
        elapsed = 0.0
        while elapsed < timeout_s:
            time.sleep(0.5)
            elapsed += 0.5
            if proc.poll() is not None: break
            cb(f"📦 Sandbox — Monitoring… {int(elapsed)}/{timeout_s}s")

        result["duration_s"] = round(time.time() - start_t, 2)
        result["exit_code"]  = proc.poll()

        # ── 4. Kill if still running ──────────────────────
        if proc.poll() is None:
            cb("📦 Sandbox — Timeout atteint — kill du processus et enfants…")
            try:
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    try: child.kill()
                    except: pass
                parent.kill()
            except: pass
            proc.wait(timeout=3)

    except PermissionError:
        result["error"] = "Accès refusé — droits insuffisants pour exécuter ce fichier"
    except FileNotFoundError:
        result["error"] = "Fichier introuvable ou interpréteur manquant"
    except Exception as e:
        result["error"] = f"Erreur lancement : {e}"
    finally:
        if monitor:
            monitor.stop()
            mon_data = monitor.get_results()
        else:
            mon_data = {}

    # ── 5. Snapshot après ─────────────────────────────────
    cb("📦 Sandbox — Snapshot filesystem après exécution…")
    all_new, all_del, all_mod = [], [], []
    for d, snap_b in snapshots_before.items():
        snap_a = _snapshot_dir(d)
        diff   = _diff_snapshots(snap_b, snap_a)
        all_new.extend(diff["created"])
        all_del.extend(diff["deleted"])
        all_mod.extend(diff["modified"])

    net_after  = _net_snapshot()
    new_conns  = _net_diff(net_before, net_after)

    # ── 6. Assemble results ───────────────────────────────
    result.update({
        "child_procs":   mon_data.get("child_procs",[]),
        "files_opened":  mon_data.get("files_opened",[]),
        "new_files":     all_new[:60],
        "deleted_files": all_del[:30],
        "modified_files":all_mod[:60],
        "net_conns":     mon_data.get("net_conns",[]),
        "new_net_conns": new_conns[:40],
        "dlls_loaded":   mon_data.get("dlls_loaded",[]),
        "cmdlines":      mon_data.get("cmdlines",[]),
        "cpu_peak":      round(max(mon_data.get("cpu_samples",[0]),default=0), 1),
        "mem_peak_kb":   max(mon_data.get("mem_samples",[0]),default=0),
    })

    # ── 7. Score ──────────────────────────────────────────
    cb("📦 Sandbox — Calcul score comportemental…")
    score, findings = _score_sandbox(result)
    result["score"]    = score
    result["findings"] = findings
    return result


def _get_launcher(path: str, ext: str) -> list:
    """Retourne la commande de lancement selon l'extension."""
    lmap = {
        '.bat':  ['cmd.exe', '/c', path],
        '.cmd':  ['cmd.exe', '/c', path],
        '.ps1':  ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-File', path],
        '.vbs':  ['wscript.exe', path],
        '.js':   ['wscript.exe', path],
        '.hta':  ['mshta.exe', path],
        '.wsf':  ['wscript.exe', path],
    }
    return lmap.get(ext, [path])