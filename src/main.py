# ============================================================
#  HARD FILE ANALYZER — main.py
#  Interface CustomTkinter · Catppuccin Macchiato
#  pip install customtkinter requests
# ============================================================

import os, sys, json, threading, time
from datetime import datetime
import customtkinter as ctk
from tkinter import filedialog, messagebox
import tkinter as tk

from config import *
from analyzer import (
    run_analysis, estimate_time, tracking_report,
    MODULES as MOD_DEF,
)

# ─── CTk theme setup ────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

FONT_MONO  = ("Consolas", 11)
FONT_MONO_S= ("Consolas", 10)
FONT_TITLE = ("Segoe UI", 13, "bold")
FONT_LABEL = ("Segoe UI", 11)
FONT_SMALL = ("Segoe UI", 10)
FONT_HUGE  = ("Segoe UI", 32, "bold")
FONT_MED   = ("Segoe UI", 14, "bold")

# ════════════════════════════════════════════════════════════
#  HELPER WIDGETS
# ════════════════════════════════════════════════════════════

def sep(parent, color=None):
    color = color or C["surface1"]
    ctk.CTkFrame(parent, height=1, fg_color=color).pack(fill="x", padx=0, pady=4)

def label(parent, text, font=None, color=None, **kw):
    return ctk.CTkLabel(parent, text=text, font=font or FONT_LABEL,
                        text_color=color or C["text"], **kw)

def badge(parent, text, bg, fg=None):
    return ctk.CTkLabel(parent, text=text, font=("Segoe UI", 10, "bold"),
                        fg_color=bg, text_color=fg or C["crust"],
                        corner_radius=4, padx=6, pady=2)

def tag_row(parent, items):
    """Horizontal row of colored tags."""
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(anchor="w", padx=0, pady=2)
    for text, color in items:
        badge(row, text, color).pack(side="left", padx=3)
    return row

def scrolled_text(parent, h=None, **kw):
    tb = ctk.CTkTextbox(parent, font=FONT_MONO_S, wrap="none",
                        fg_color=C["mantle"], text_color=C["text"],
                        scrollbar_button_color=C["surface1"],
                        height=h or 300, **kw)
    return tb

def section_title(parent, text, icon=""):
    f = ctk.CTkFrame(parent, fg_color=C["surface0"], corner_radius=6)
    f.pack(fill="x", padx=6, pady=(6,2))
    label(f, f" {icon}  {text}", font=("Segoe UI", 11, "bold"),
          color=C["lavender"]).pack(anchor="w", padx=10, pady=5)
    return f


# ════════════════════════════════════════════════════════════
#  MODULE TOGGLE CARD
# ════════════════════════════════════════════════════════════

class ModuleCard(ctk.CTkFrame):
    def __init__(self, parent, mid: str, enabled_dict: dict, on_change=None):
        super().__init__(parent, fg_color=C["surface0"], corner_radius=8)
        self.mid = mid
        self.enabled = enabled_dict
        self.on_change = on_change
        cfg = MOD_DEF[mid]

        self.var = ctk.BooleanVar(value=cfg["default"])
        self.enabled[mid] = cfg["default"]

        # Icon + name
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(8,2))
        label(top, cfg["icon"] + "  " + cfg["name"],
              font=("Segoe UI", 11, "bold"), color=C["lavender"]).pack(side="left")
        self._sw = ctk.CTkSwitch(top, text="", variable=self.var,
                                  width=44, height=22,
                                  button_color=C["mauve"],
                                  button_hover_color=C["lavender"],
                                  progress_color=C["blue"],
                                  fg_color=C["surface2"],
                                  command=self._toggle)
        self._sw.pack(side="right")

        label(self, cfg["desc"], font=FONT_SMALL, color=C["subtext0"],
              justify="left", wraplength=180).pack(anchor="w", padx=10, pady=(0,8))

    def _toggle(self):
        self.enabled[self.mid] = self.var.get()
        col = C["surface1"] if self.var.get() else C["crust"]
        self.configure(fg_color=col if self.var.get() else C["surface0"])
        if self.on_change: self.on_change()

    def set(self, val: bool):
        self.var.set(val)
        self.enabled[self.mid] = val


# ════════════════════════════════════════════════════════════
#  RESULT PANELS
# ════════════════════════════════════════════════════════════

class StaticPanel(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=C["base"])

    def render(self, r: dict):
        for w in self.winfo_children(): w.destroy()
        if not r: return

        # Hashes
        section_title(self, "Hashes cryptographiques", "🔑")
        for alg, val in r.get("hashes",{}).items():
            if alg == "error": continue
            row = ctk.CTkFrame(self, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=1)
            label(row, alg.upper(), font=("Consolas",10,"bold"),
                  color=C["mauve"]).pack(side="left", padx=(4,8))
            label(row, val, font=FONT_MONO_S, color=C["subtext1"]).pack(side="left")

        # Type detection
        section_title(self, "Type de fichier", "🧬")
        ftype = r.get("type",{})
        f = ctk.CTkFrame(self, fg_color="transparent")
        f.pack(fill="x", padx=12, pady=4)
        label(f, f"Type détecté :  {ftype.get('type','?')}",
              color=C["teal"]).pack(anchor="w")
        label(f, f"Magic bytes  :  {ftype.get('magic','')}",
              font=FONT_MONO_S, color=C["subtext0"]).pack(anchor="w")
        packed = ftype.get("packed", False)
        pcol = C["red"] if packed else C["green"]
        label(f, f"Packing       :  {'⚠️ ' + ftype.get('packer','?') if packed else '✅ Aucun packer détecté'}",
              color=pcol).pack(anchor="w")

        # Extension check
        extc = r.get("ext_check",{})
        if extc.get("mismatch"):
            section_title(self, "Extension ↔ Contenu : MISMATCH", "⚠️")
            f2 = ctk.CTkFrame(self, fg_color=C["mantle"], corner_radius=6)
            f2.pack(fill="x", padx=8, pady=4)
            sev_col = C["red"] if extc["severity"]=="high" else C["yellow"]
            label(f2, f"Extension déclarée : {extc.get('extension','')}",
                  color=C["text"]).pack(anchor="w", padx=10, pady=2)
            label(f2, f"Type réel          : {extc.get('detected','')}",
                  color=sev_col).pack(anchor="w", padx=10, pady=2)
            label(f2, f"Sévérité           : {extc.get('severity','').upper()}",
                  color=sev_col, font=("Segoe UI",11,"bold")).pack(anchor="w",padx=10,pady=2)

        # Entropy
        ent = r.get("entropy",{})
        section_title(self, "Entropie Shannon", "📊")
        f3 = ctk.CTkFrame(self, fg_color="transparent")
        f3.pack(fill="x", padx=12, pady=4)
        ecol = C["red"] if ent.get("high_entropy") else C["green"]
        label(f3, f"Entropie globale : {ent.get('overall',0.0):.4f} / 8.0",
              color=ecol).pack(anchor="w")
        if ent.get("high_entropy"):
            label(f3, "⚠️  Entropie élevée → obfuscation / chiffrement probable",
                  color=C["red"]).pack(anchor="w")
        secs = ent.get("suspicious_sections",[])
        if secs:
            label(f3, f"{len(secs)} section(s) à haute entropie :", color=C["yellow"]).pack(anchor="w")
            for s in secs[:8]:
                label(f3, f"    offset {s['offset']}  →  {s['entropy']:.4f}",
                      font=FONT_MONO_S, color=C["peach"]).pack(anchor="w")

        # Metadata
        section_title(self, "Métadonnées", "🗂️")
        meta = r.get("metadata",{})
        f4 = ctk.CTkFrame(self, fg_color="transparent")
        f4.pack(fill="x", padx=12, pady=4)
        for k,v in meta.items():
            if k == "error": continue
            kcol = C["subtext0"]; vcol = C["text"]
            if k=="signature" and v=="Valid": vcol=C["green"]
            elif k=="signature": vcol=C["yellow"]
            row2 = ctk.CTkFrame(f4, fg_color="transparent")
            row2.pack(fill="x", pady=1)
            label(row2, f"{k:<20}", font=("Consolas",10), color=kcol).pack(side="left")
            label(row2, str(v), font=FONT_MONO_S, color=vcol).pack(side="left")

        # Suspicious strings
        sus = r.get("strings",{}).get("suspicious",[])
        section_title(self, f"Strings suspects ({len(sus)} / {r.get('strings',{}).get('total',0)})", "🔤")
        tb = scrolled_text(self, h=200)
        tb.pack(fill="x", padx=8, pady=4)
        if sus:
            for item in sus[:60]:
                tb.insert("end", f"[{item['pattern']}]\n  {item['string']}\n\n")
        else:
            tb.insert("end", "Aucun string suspect détecté.")
        tb.configure(state="disabled")


class HeuristicPanel(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=C["base"])

    def _block(self, title, icon, items, color=None):
        if not items: return
        col = color or C["red"]
        section_title(self, f"{title}  ({len(items)})", icon)
        f = ctk.CTkFrame(self, fg_color=C["mantle"], corner_radius=6)
        f.pack(fill="x", padx=8, pady=4)
        for item in items[:20]:
            label(f, f"  • {item}", color=col, font=FONT_MONO_S).pack(anchor="w", padx=6, pady=1)

    def render(self, r: dict):
        for w in self.winfo_children(): w.destroy()
        if not r: return
        self._block("Indicateurs Ransomware", "🔒", r.get("ransomware",[]))
        self._block("Code Injection APIs",    "💉", r.get("injection",[]))
        self._block("Anti-Debug",             "🐛", r.get("anti_debug",[]))
        self._block("Anti-VM / Anti-Sandbox", "🖥️", r.get("anti_vm",[]), C["maroon"])
        self._block("Persistence / Startup",  "📌", r.get("persistence",[]), C["yellow"])
        self._block("Élévation de Privilèges","⬆️", r.get("privesc",[]))

        section_title(self, "Obfuscation", "🌀")
        f = ctk.CTkFrame(self, fg_color="transparent")
        f.pack(fill="x", padx=12, pady=4)
        val = r.get("obfuscation", False)
        label(f, "⚠️ Obfuscation détectée (base64 ou hex masqué)" if val
              else "✅ Aucune obfuscation évidente",
              color=C["red"] if val else C["green"]).pack(anchor="w")


class NetworkPanel(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=C["base"])

    def render(self, r: dict):
        for w in self.winfo_children(): w.destroy()
        if not r: return
        for title, icon, key, color in [
            ("URLs extraites",        "🔗", "urls",             C["blue"]),
            ("Adresses IP externes",  "📡", "ips",              C["red"]),
            ("Domaines suspects",     "🌍", "domains_suspicious",C["maroon"]),
            ("Payloads Base64",       "📦", "base64_payloads",  C["peach"]),
        ]:
            items = r.get(key, [])
            section_title(self, f"{title}  ({len(items)})", icon)
            if items:
                tb = scrolled_text(self, h=110)
                tb.pack(fill="x", padx=8, pady=4)
                for it in items[:40]:
                    tb.insert("end", str(it) + "\n")
                tb.configure(state="disabled")
            else:
                f = ctk.CTkFrame(self, fg_color="transparent")
                f.pack(fill="x", padx=12, pady=2)
                label(f, "  Aucun élément détecté.", color=C["subtext0"]).pack(anchor="w")


class SystemPanel(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=C["base"])

    def render(self, r: dict):
        for w in self.winfo_children(): w.destroy()
        if not r: return

        def flag(title, icon, val, yes_text, no_text, col=C["red"]):
            section_title(self, title, icon)
            f = ctk.CTkFrame(self, fg_color="transparent")
            f.pack(fill="x", padx=12, pady=4)
            label(f, (f"⚠️  {yes_text}" if val else f"✅  {no_text}"),
                  color=col if val else C["green"]).pack(anchor="w")

        flag("Élévation de privilèges", "⬆️",
             r.get("privilege_req"), "Privilèges élevés requis", "Aucun privilege élevé")
        flag("Modification démarrage", "📌",
             r.get("startup"), "Persistence au démarrage détectée", "Pas de persistence startup")
        flag("Chargement pilote kernel", "🔧",
             r.get("driver_load"), "Chargement driver kernel suspect", "Aucun driver load détecté",
             C["maroon"])

        for title, icon, key, col in [
            ("Fichiers système sensibles", "🗄️",  "sensitive_files", C["red"]),
            ("Clés registre modifiées",    "🗝️",  "registry_keys",   C["yellow"]),
        ]:
            items = r.get(key, [])
            section_title(self, f"{title}  ({len(items)})", icon)
            f = ctk.CTkFrame(self, fg_color="transparent")
            f.pack(fill="x", padx=12, pady=4)
            if items:
                for it in items[:15]:
                    label(f, f"  • {it}", color=col, font=FONT_MONO_S).pack(anchor="w", pady=1)
            else:
                label(f, "  Aucun accès détecté.", color=C["subtext0"]).pack(anchor="w")


class IQPanel(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=C["base"])

    def _list_block(self, title, icon, items, col=C["yellow"]):
        section_title(self, f"{title}  ({len(items)})", icon)
        f = ctk.CTkFrame(self, fg_color="transparent")
        f.pack(fill="x", padx=12, pady=4)
        if items:
            for it in items:
                label(f, it, color=col).pack(anchor="w", pady=2)
        else:
            label(f, "  ✅  Aucune anomalie détectée.", color=C["green"]).pack(anchor="w")

    def render(self, r: dict):
        for w in self.winfo_children(): w.destroy()
        if not r: return
        self._list_block("Anomalies Temporelles",    "🕰️",  r.get("temporal",[]),      C["peach"])
        self._list_block("Anomalies de Structure",   "🏗️",  r.get("structure",[]),     C["yellow"])
        self._list_block("Contradictions Metadata",  "🔄",  r.get("metadata_contra",[]),C["maroon"])
        self._list_block("Anomalies Logiques",       "🧩",  r.get("logical",[]),        C["red"])


class CloudPanel(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=C["base"])

    def render(self, r: dict):
        for w in self.winfo_children(): w.destroy()
        if not r: return
        if r.get("error"):
            section_title(self, "VirusTotal — Erreur", "☁️")
            f = ctk.CTkFrame(self, fg_color="transparent")
            f.pack(fill="x", padx=12, pady=8)
            label(f, f"⚠️  {r['error']}", color=C["red"]).pack(anchor="w")
            return

        det = r.get("detections", 0)
        tot = r.get("total", 0)
        rate = r.get("rate","0%")
        col  = C["red"] if det > 3 else (C["yellow"] if det > 0 else C["green"])

        section_title(self, "Résultat VirusTotal", "☁️")
        f = ctk.CTkFrame(self, fg_color=C["mantle"], corner_radius=8)
        f.pack(fill="x", padx=8, pady=8)
        label(f, f"{'⚠️ ' if det else '✅ '} {det} / {tot} moteurs",
              font=("Segoe UI",18,"bold"), color=col).pack(pady=(12,4))
        label(f, f"Taux de détection : {rate}", color=col).pack(pady=2)
        found_txt = "Hash connu" if r.get("found") else "Hash inconnu (uploadé)"
        label(f, found_txt, color=C["subtext0"], font=FONT_SMALL).pack(pady=(2,12))

        if r.get("permalink"):
            section_title(self, "Lien VirusTotal", "🔗")
            tb = scrolled_text(self, h=40)
            tb.pack(fill="x", padx=8, pady=4)
            tb.insert("end", r["permalink"])
            tb.configure(state="disabled")

        engines = r.get("engines",{})
        if engines:
            section_title(self, f"Moteurs positifs ({len(engines)})", "🦠")
            tb2 = scrolled_text(self, h=200)
            tb2.pack(fill="x", padx=8, pady=4)
            for eng, res in engines.items():
                tb2.insert("end", f"  {eng:<30}  {res}\n")
            tb2.configure(state="disabled")


class SandboxPanel(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=C["base"])

    def render(self, r: dict):
        for w in self.winfo_children(): w.destroy()
        if not r: return

        section_title(self, "Information sandbox", "📦")
        f0 = ctk.CTkFrame(self, fg_color=C["surface0"], corner_radius=6)
        f0.pack(fill="x", padx=8, pady=6)
        label(f0, r.get("note",""), color=C["subtext1"],
              font=FONT_SMALL, wraplength=580).pack(padx=10, pady=8)

        if not r.get("executable"):
            return

        flag_val = r.get("anti_vm", False)
        section_title(self, "Anti-VM / Anti-sandbox", "🖥️")
        fv = ctk.CTkFrame(self, fg_color="transparent")
        fv.pack(fill="x", padx=12, pady=4)
        label(fv, "⚠️  Anti-VM détecté" if flag_val else "✅  Aucun anti-VM détecté",
              color=C["red"] if flag_val else C["green"]).pack(anchor="w")

        def block(title, icon, items, key=None, col=C["peach"]):
            section_title(self, f"{title}  ({len(items)})", icon)
            f = ctk.CTkFrame(self, fg_color="transparent")
            f.pack(fill="x", padx=12, pady=4)
            if items:
                for it in items[:15]:
                    if isinstance(it, dict):
                        txt = "  •  " + " | ".join(str(v) for v in it.values())
                    else:
                        txt = f"  •  {it}"
                    label(f, txt, color=col, font=FONT_MONO_S).pack(anchor="w", pady=1)
            else:
                label(f, "  Aucun élément.", color=C["subtext0"]).pack(anchor="w")

        block("API Calls prédits",         "📟", r.get("api_calls",[]),        col=C["blue"])
        block("Fichiers système affectés", "📁", r.get("files_expected",[]),   col=C["yellow"])
        block("Connexions réseau prédites","📡", r.get("network_expected",[]), col=C["red"])
        block("Clés registre prédites",    "🗝️", r.get("registry_expected",[]),col=C["maroon"])


class ScorePanel(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=C["base"])

    def render(self, r: dict, dont_trust: bool):
        for w in self.winfo_children(): w.destroy()
        if not r: return

        score = r.get("score", 0)
        label_txt, col, icon = get_risk(score)

        # Score gauge
        gauge_f = ctk.CTkFrame(self, fg_color=C["mantle"], corner_radius=12)
        gauge_f.pack(fill="x", padx=20, pady=20)

        label(gauge_f, f"{icon}  {score:>3} / 100",
              font=FONT_HUGE, color=col).pack(pady=(20,4))
        label(gauge_f, label_txt,
              font=("Segoe UI",16,"bold"), color=col).pack(pady=(0,4))

        if dont_trust:
            label(gauge_f,
                  "⚠️  MODE DON'T TRUST — Résultat à titre indicatif uniquement",
                  color=C["yellow"], font=("Segoe UI",10,"bold")).pack(pady=(4,8))
        else:
            label(gauge_f, " ", font=FONT_SMALL).pack()

        # Progress bar
        bar = ctk.CTkProgressBar(gauge_f, width=500, height=14,
                                  progress_color=col, fg_color=C["surface0"])
        bar.set(score / 100)
        bar.pack(pady=(4,20))

        # Risk scale legend
        scale_f = ctk.CTkFrame(self, fg_color="transparent")
        scale_f.pack(fill="x", padx=20, pady=4)
        for lo, hi, lbl, c, ico in RISK_LEVELS:
            tag = ctk.CTkLabel(scale_f, text=f"{ico} {lo}–{hi} {lbl}",
                               font=("Segoe UI",9,"bold"),
                               fg_color=c, text_color=C["crust"],
                               corner_radius=4, padx=6, pady=3)
            tag.pack(side="left", padx=4)

        # Factors
        factors = r.get("factors", [])
        if factors:
            section_title(self, "Facteurs de risque", "📋")
            ff = ctk.CTkScrollableFrame(self, height=220, fg_color=C["mantle"], corner_radius=8)
            ff.pack(fill="x", padx=16, pady=8)
            for factor in factors:
                label(ff, f"  ⬦  {factor}", color=C["peach"]).pack(anchor="w", pady=2)

        # Module scores
        section_title(self, "Scores par module", "📊")
        ms = ctk.CTkFrame(self, fg_color="transparent")
        ms.pack(fill="x", padx=16, pady=4)
        return ms


# ════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ════════════════════════════════════════════════════════════

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"🛡️  {APP_TITLE}  v{APP_VERSION}")
        self.geometry("1180x760")
        self.minsize(900, 600)
        self.configure(fg_color=C["crust"])
        self.resizable(True, True)

        self._enabled   = {}   # module_id → bool
        self._vt_key    = ctk.StringVar(value="")
        self._dont_trust= ctk.BooleanVar(value=False)
        self._tracking  = ctk.BooleanVar(value=False)
        self._filepath  = ctk.StringVar(value="")
        self._running   = False
        self._results   = {}

        self._build_ui()

    # ── UI BUILD ─────────────────────────────────────────────

    def _build_ui(self):
        # ── Header
        hdr = ctk.CTkFrame(self, fg_color=C["mantle"], height=56, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        label(hdr, "🛡️", font=("Segoe UI",20)).pack(side="left", padx=14)
        label(hdr, APP_TITLE, font=("Segoe UI",15,"bold"),
              color=C["lavender"]).pack(side="left")
        label(hdr, f"v{APP_VERSION}", font=FONT_SMALL,
              color=C["overlay0"]).pack(side="left", padx=6, pady=0)

        self._dont_trust_btn = ctk.CTkButton(
            hdr, text="🔴  DON'T TRUST  OFF", font=("Segoe UI",10,"bold"),
            fg_color=C["surface0"], hover_color=C["surface1"],
            text_color=C["overlay1"], width=155, height=30, corner_radius=6,
            command=self._toggle_dont_trust)
        self._dont_trust_btn.pack(side="right", padx=8)

        self._tracking_btn = ctk.CTkButton(
            hdr, text="📋  TRACKING  OFF", font=("Segoe UI",10,"bold"),
            fg_color=C["surface0"], hover_color=C["surface1"],
            text_color=C["overlay1"], width=140, height=30, corner_radius=6,
            command=self._toggle_tracking)
        self._tracking_btn.pack(side="right", padx=4)

        # ── Body (sidebar + main)
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)

        self._build_sidebar(body)
        self._build_main(body)

    def _build_sidebar(self, parent):
        sb = ctk.CTkScrollableFrame(parent, width=224,
                                     fg_color=C["mantle"], corner_radius=0)
        sb.pack(side="left", fill="y")

        label(sb, "  MODULES", font=("Segoe UI",10,"bold"),
              color=C["overlay0"]).pack(anchor="w", padx=6, pady=(10,4))

        self._cards = {}
        for mid in MODULES:
            card = ModuleCard(sb, mid, self._enabled, on_change=self._update_estimate)
            card.pack(fill="x", padx=6, pady=3)
            self._cards[mid] = card

        sep(sb, C["surface0"])

        # VT API key
        label(sb, "  VIRUSTOTAL API KEY", font=("Segoe UI",10,"bold"),
              color=C["overlay0"]).pack(anchor="w", padx=6, pady=(6,2))
        self._vt_entry = ctk.CTkEntry(
            sb, textvariable=self._vt_key, placeholder_text="Votre clé API…",
            fg_color=C["surface0"], border_color=C["surface1"],
            text_color=C["text"], font=FONT_MONO_S, show="•")
        self._vt_entry.pack(fill="x", padx=6, pady=2)
        ctk.CTkButton(sb, text="👁 Afficher", font=FONT_SMALL,
                       fg_color=C["surface0"], hover_color=C["surface1"],
                       text_color=C["subtext0"], height=26,
                       command=self._toggle_vt_vis).pack(fill="x", padx=6, pady=(0,6))

        sep(sb, C["surface0"])

        # Quick presets
        label(sb, "  PRESETS", font=("Segoe UI",10,"bold"),
              color=C["overlay0"]).pack(anchor="w", padx=6, pady=(4,2))
        for name, mids in [
            ("⚡ Rapide",  ["static","heuristic"]),
            ("🔍 Complet", list(MODULES.keys())),
            ("🌐 Cloud",   ["static","cloud"]),
        ]:
            ctk.CTkButton(sb, text=name, font=FONT_SMALL,
                           fg_color=C["surface0"], hover_color=C["blue"],
                           text_color=C["text"], height=30, corner_radius=6,
                           command=lambda m=mids: self._apply_preset(m)
                           ).pack(fill="x", padx=6, pady=2)

    def _build_main(self, parent):
        main = ctk.CTkFrame(parent, fg_color=C["base"], corner_radius=0)
        main.pack(side="left", fill="both", expand=True)

        # ── Top bar: file selector + scan
        top = ctk.CTkFrame(main, fg_color=C["mantle"], height=72, corner_radius=0)
        top.pack(fill="x")
        top.pack_propagate(False)

        sel_f = ctk.CTkFrame(top, fg_color="transparent")
        sel_f.pack(side="left", fill="both", expand=True, padx=12, pady=10)

        self._path_entry = ctk.CTkEntry(
            sel_f, textvariable=self._filepath,
            placeholder_text="📂  Sélectionner un fichier ou dossier…",
            fg_color=C["surface0"], border_color=C["surface1"],
            text_color=C["text"], font=FONT_LABEL, height=36)
        self._path_entry.pack(side="left", fill="x", expand=True, padx=(0,8))

        ctk.CTkButton(sel_f, text="📁 Fichier", width=90, height=36,
                       fg_color=C["surface0"], hover_color=C["surface1"],
                       text_color=C["subtext1"], font=FONT_SMALL,
                       command=self._pick_file).pack(side="left", padx=2)
        ctk.CTkButton(sel_f, text="📂 Dossier", width=90, height=36,
                       fg_color=C["surface0"], hover_color=C["surface1"],
                       text_color=C["subtext1"], font=FONT_SMALL,
                       command=self._pick_dir).pack(side="left", padx=2)

        self._scan_btn = ctk.CTkButton(
            top, text="  ▶  SCANNER", font=("Segoe UI",13,"bold"),
            width=140, height=52, corner_radius=8,
            fg_color=C["mauve"], hover_color=C["lavender"],
            text_color=C["crust"], command=self._launch_scan)
        self._scan_btn.pack(side="right", padx=16, pady=10)

        # ── Status bar
        status_f = ctk.CTkFrame(main, fg_color=C["surface0"], height=32, corner_radius=0)
        status_f.pack(fill="x")
        status_f.pack_propagate(False)

        self._status_lbl = label(status_f, "  Prêt.", color=C["subtext0"], font=FONT_SMALL)
        self._status_lbl.pack(side="left", padx=8)

        self._est_lbl = label(status_f, "", color=C["blue"], font=FONT_SMALL)
        self._est_lbl.pack(side="right", padx=12)

        self._progress = ctk.CTkProgressBar(main, height=4,
                                              progress_color=C["mauve"],
                                              fg_color=C["surface0"])
        self._progress.set(0)
        self._progress.pack(fill="x")

        # ── Results tabview
        self._tabs = ctk.CTkTabview(main, fg_color=C["base"],
                                     segmented_button_fg_color=C["surface0"],
                                     segmented_button_selected_color=C["mauve"],
                                     segmented_button_selected_hover_color=C["lavender"],
                                     segmented_button_unselected_color=C["surface0"],
                                     segmented_button_unselected_hover_color=C["surface1"],
                                     text_color=C["text"],
                                     text_color_disabled=C["overlay0"])
        self._tabs.pack(fill="both", expand=True, padx=4, pady=4)

        tab_map = [
            ("📊 Score",      ScorePanel),
            ("🔬 Statique",   StaticPanel),
            ("🧠 Heuristique",HeuristicPanel),
            ("🌐 Réseau",     NetworkPanel),
            ("⚙️ Système",   SystemPanel),
            ("🧩 IQ Mode",   IQPanel),
            ("☁️ Cloud",     CloudPanel),
            ("📦 Sandbox",   SandboxPanel),
            ("📋 Tracking",  None),
        ]
        self._panels = {}
        for name, cls in tab_map:
            t = self._tabs.add(name)
            t.configure(fg_color=C["base"])
            if cls:
                panel = cls(t)
                panel.pack(fill="both", expand=True)
                self._panels[name] = panel
            elif name == "📋 Tracking":
                self._tracking_box = scrolled_text(t, h=400)
                self._tracking_box.pack(fill="both", expand=True, padx=4, pady=4)
                self._panels[name] = self._tracking_box

        self._update_estimate()

    # ── CONTROLS ─────────────────────────────────────────────

    def _toggle_dont_trust(self):
        val = not self._dont_trust.get()
        self._dont_trust.set(val)
        if val:
            self._dont_trust_btn.configure(
                text="🔴  DON'T TRUST  ON",
                fg_color=C["red"], text_color=C["crust"])
        else:
            self._dont_trust_btn.configure(
                text="🔴  DON'T TRUST  OFF",
                fg_color=C["surface0"], text_color=C["overlay1"])

    def _toggle_tracking(self):
        val = not self._tracking.get()
        self._tracking.set(val)
        if val:
            self._tracking_btn.configure(
                text="📋  TRACKING  ON",
                fg_color=C["blue"], text_color=C["crust"])
        else:
            self._tracking_btn.configure(
                text="📋  TRACKING  OFF",
                fg_color=C["surface0"], text_color=C["overlay1"])

    def _toggle_vt_vis(self):
        cur = self._vt_entry.cget("show")
        self._vt_entry.configure(show="" if cur == "•" else "•")

    def _pick_file(self):
        p = filedialog.askopenfilename(title="Sélectionner un fichier")
        if p:
            self._filepath.set(p)
            self._update_estimate()

    def _pick_dir(self):
        p = filedialog.askdirectory(title="Sélectionner un dossier")
        if p:
            self._filepath.set(p)
            self._update_estimate()

    def _apply_preset(self, mids):
        for mid, card in self._cards.items():
            card.set(mid in mids)
        self._update_estimate()

    def _update_estimate(self):
        path = self._filepath.get().strip()
        if not path or not os.path.exists(path):
            self._est_lbl.configure(text="")
            return
        try:
            est = estimate_time(path, self._enabled)
            self._est_lbl.configure(
                text=f"⏱  Durée estimée : {est['human']}  ·  {est['files']} fichier(s)  ·  {est['size_mb']} MB")
        except:
            self._est_lbl.configure(text="")

    # ── SCAN ─────────────────────────────────────────────────

    def _launch_scan(self):
        if self._running: return
        path = self._filepath.get().strip()
        if not path:
            messagebox.showwarning("Aucun fichier", "Veuillez sélectionner un fichier ou dossier.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Introuvable", f"Le chemin n'existe pas :\n{path}")
            return
        if not any(self._enabled.values()):
            messagebox.showwarning("Aucun module", "Activez au moins un module d'analyse.")
            return

        # Show tracking report first
        if self._tracking.get():
            report = tracking_report(path, self._enabled, self._vt_key.get().strip())
            box = self._panels.get("📋 Tracking")
            if box:
                box.configure(state="normal")
                box.delete("0.0","end")
                box.insert("end", report)
                box.configure(state="disabled")
            self._tabs.set("📋 Tracking")

            if not messagebox.askyesno("Mode Tracking",
                    "Le rapport pré-analyse a été généré.\n\nLancer le scan maintenant ?"):
                return

        self._running = True
        self._scan_btn.configure(text="  ⏳  EN COURS…", state="disabled",
                                  fg_color=C["overlay0"])
        self._progress.set(0)
        self._progress.configure(mode="indeterminate")
        self._progress.start()

        threading.Thread(target=self._run_thread, args=(path,), daemon=True).start()

    def _run_thread(self, path: str):
        steps = [k for k, v in self._enabled.items() if v]
        total = len(steps) + 1
        done  = [0]

        def cb(msg):
            self._status_lbl.configure(text=f"  {msg}")
            done[0] += 0.3
            self.after(0, lambda: self._progress.set(min(done[0]/total, 0.95)))

        try:
            results = run_analysis(
                path, self._enabled,
                vt_key=self._vt_key.get().strip(),
                dont_trust=self._dont_trust.get(),
                cb=cb,
            )
            self.after(0, lambda: self._show_results(results))
        except Exception as e:
            self.after(0, lambda: self._on_error(str(e)))

    def _show_results(self, r: dict):
        self._results = r
        self._running = False
        self._progress.stop()
        self._progress.configure(mode="determinate")
        self._progress.set(1.0)
        self._scan_btn.configure(text="  ▶  SCANNER", state="normal",
                                  fg_color=C["mauve"])
        self._status_lbl.configure(
            text=f"  ✅  Analyse terminée — {datetime.now().strftime('%H:%M:%S')}",
            text_color=C["green"])

        final = r.get("final",{})

        # Score panel
        sp = self._panels.get("📊 Score")
        if sp:
            ms = sp.render(final, r.get("dont_trust", False))
            # Draw per-module score bars in ms (if returned)
            if ms:
                for mid, cfg in MODULES.items():
                    if self._enabled.get(mid) and mid in r:
                        s = r[mid].get("score",0)
                        label_txt, col, _ = get_risk(s)
                        row = ctk.CTkFrame(ms, fg_color="transparent")
                        row.pack(fill="x", pady=2, padx=4)
                        label(row, f"{cfg['icon']} {cfg['name']}", font=FONT_SMALL,
                              color=C["subtext0"]).pack(side="left", padx=(0,8))
                        pb = ctk.CTkProgressBar(row, width=180, height=8,
                                                 progress_color=col, fg_color=C["surface0"])
                        pb.set(s/100)
                        pb.pack(side="left")
                        label(row, f"{s:>3}", font=FONT_MONO_S, color=col).pack(side="left",padx=6)

        map_p = {
            "🔬 Statique":    ("static",    self._panels.get("🔬 Statique")),
            "🧠 Heuristique": ("heuristic", self._panels.get("🧠 Heuristique")),
            "🌐 Réseau":      ("network",   self._panels.get("🌐 Réseau")),
            "⚙️ Système":    ("system",    self._panels.get("⚙️ Système")),
            "🧩 IQ Mode":    ("iq",        self._panels.get("🧩 IQ Mode")),
            "☁️ Cloud":      ("cloud",     self._panels.get("☁️ Cloud")),
            "📦 Sandbox":    ("sandbox",   self._panels.get("📦 Sandbox")),
        }
        for tab_name, (key, panel) in map_p.items():
            if panel and key in r:
                panel.render(r[key])

        self._tabs.set("📊 Score")

    def _on_error(self, msg: str):
        self._running = False
        self._progress.stop()
        self._progress.configure(mode="determinate")
        self._progress.set(0)
        self._scan_btn.configure(text="  ▶  SCANNER", state="normal",
                                  fg_color=C["mauve"])
        self._status_lbl.configure(text=f"  ❌  Erreur : {msg}", text_color=C["red"])
        messagebox.showerror("Erreur d'analyse", msg)


# ════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = App()
    app.mainloop()