"""
NetScan Pro — Couche logique centrale
Gère : SNMP, ping, détection de type, formatage, base de données
Compatible pysnmp 7+ (async) et pysnmp legacy (sync)
"""

import asyncio
import ipaddress
import socket
import sqlite3
import threading
import datetime
import csv
import io
import os
from typing import Optional

# ── Dépendances optionnelles ──────────────────────────────────────────────────

SNMP_AVAILABLE = False
SNMP_LEGACY    = False

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        get_cmd, SnmpEngine, CommunityData,
        UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
    )
    SNMP_AVAILABLE = True
except ImportError:
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData,
            UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
        )
        SNMP_AVAILABLE = True
        SNMP_LEGACY    = True
    except ImportError:
        pass

try:
    from ping3 import ping as _ping3
    PING_AVAILABLE = True
except ImportError:
    PING_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle,
        Paragraph, Spacer, HRFlowable
    )
    from reportlab.lib.enums import TA_CENTER
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# ── Constantes ────────────────────────────────────────────────────────────────

OIDS = {
    "sysDescr":    "1.3.6.1.2.1.1.1.0",
    "sysUpTime":   "1.3.6.1.2.1.1.3.0",
    "sysContact":  "1.3.6.1.2.1.1.4.0",
    "sysName":     "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "ifNumber":    "1.3.6.1.2.1.2.1.0",
}

DEVICE_TYPES = {
    "router":   {"label": "Routeur",     "icon": "🔀", "color": "#185FA5"},
    "switch":   {"label": "Switch",      "icon": "🔌", "color": "#0F6E56"},
    "server":   {"label": "Serveur",     "icon": "🖥️",  "color": "#3B6D11"},
    "printer":  {"label": "Imprimante",  "icon": "🖨️",  "color": "#712B13"},
    "firewall": {"label": "Pare-feu",    "icon": "🛡️",  "color": "#533AB7"},
    "pc":       {"label": "Poste",       "icon": "💻", "color": "#854F0B"},
    "unknown":  {"label": "Inconnu",     "icon": "❓", "color": "#5F5E5A"},
}


# ── Fonctions réseau ──────────────────────────────────────────────────────────

def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """Vérifie si un hôte répond. Utilise ping3 si disponible, sinon socket TCP."""
    if PING_AVAILABLE:
        try:
            result = _ping3(ip, timeout=timeout, unit="ms")
            return result is not None and result is not False
        except Exception:
            pass
    # Fallback TCP ports 80, 443, 22
    for port in (80, 443, 22):
        try:
            with socket.create_connection((ip, port), timeout=0.8):
                return True
        except Exception:
            pass
    return False


def resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    """Résolution DNS inverse."""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "—"


def snmp_get_bulk(ip: str, community: str, oids: dict,
                  version: int = 1, timeout: int = 2) -> dict:
    """
    Récupère plusieurs OIDs SNMP sur un équipement.
    Supporte pysnmp 7+ (asyncio) et pysnmp legacy (synchrone).
    """
    results = {name: "—" for name in oids}
    if not SNMP_AVAILABLE:
        return results

    if SNMP_LEGACY:
        # API synchrone pysnmp ≤ 4.x
        for name, oid in oids.items():
            try:
                iterator = getCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=version),
                    UdpTransportTarget((ip, 161), timeout=timeout, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
                err_ind, err_st, _, var_binds = next(iterator)
                if not err_ind and not err_st:
                    for vb in var_binds:
                        results[name] = str(vb[1])
            except Exception:
                pass
        return results

    # API asynchrone pysnmp 7+
    async def _async_bulk():
        try:
            snmp_engine = SnmpEngine()
            transport = await UdpTransportTarget.create(
                (ip, 161), timeout=timeout, retries=1
            )
            oid_objects = [ObjectType(ObjectIdentity(oid)) for oid in oids.values()]
            err_ind, err_st, _, var_binds = await get_cmd(
                snmp_engine,
                CommunityData(community, mpModel=version),
                transport,
                ContextData(),
                *oid_objects
            )
            snmp_engine.close_dispatcher()
            if err_ind or err_st:
                return {}
            out = {}
            for (name, _), vb in zip(oids.items(), var_binds):
                out[name] = str(vb[1])
            return out
        except Exception:
            return {}

    try:
        data = asyncio.run(_async_bulk())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            data = loop.run_until_complete(_async_bulk())
        finally:
            loop.close()

    for name, val in data.items():
        results[name] = val if val else "—"
    return results


def detect_device_type(sys_descr: str) -> str:
    """Identifie le type d'équipement à partir de sysDescr."""
    if not sys_descr or sys_descr == "—":
        return "unknown"
    d = sys_descr.lower()
    if any(k in d for k in ["router", "cisco ios", "junos", "routeur"]):
        return "router"
    if any(k in d for k in ["switch", "catalyst", "nexus", "commutateur"]):
        return "switch"
    if any(k in d for k in ["linux", "windows server", "ubuntu", "debian",
                              "centos", "freebsd", "proxmox", "esxi", "vmware"]):
        return "server"
    if any(k in d for k in ["print", "hp laserjet", "brother", "canon",
                              "epson", "imprimante"]):
        return "printer"
    if any(k in d for k in ["firewall", "fortigate", "pfsense", "asa"]):
        return "firewall"
    if any(k in d for k in ["windows", "workstation", "desktop"]):
        return "pc"
    return "unknown"


def format_uptime(raw: str) -> str:
    """Convertit sysUpTime (centièmes de secondes Timeticks) en texte lisible."""
    if not raw or raw == "—":
        return "—"
    try:
        val = raw.replace("Timeticks:", "").strip()
        if "(" in val:
            val = val.split("(")[1].split(")")[0]
        ticks = int(val)
        total_s = ticks // 100
        days  = total_s // 86400
        hours = (total_s % 86400) // 3600
        mins  = (total_s % 3600) // 60
        return f"{days}j {hours}h {mins}m"
    except Exception:
        return raw[:24] if len(raw) > 24 else raw


def uptime_to_seconds(raw: str) -> int:
    """Convertit sysUpTime en secondes (pour comparaison/tri)."""
    if not raw or raw == "—":
        return 0
    try:
        val = raw.replace("Timeticks:", "").strip()
        if "(" in val:
            val = val.split("(")[1].split(")")[0]
        return int(val) // 100
    except Exception:
        return 0


def scan_host_full(ip: str, community: str, version: int,
                   timeout: int) -> dict:
    """
    Scanne un seul hôte : ping + SNMP.
    Retourne un dictionnaire complet de l'équipement.
    """
    device = {
        "ip": ip,
        "status": "Inactif",
        "hostname": "—",
        "sysName": "—",
        "sysDescr": "—",
        "sysUpTime": "—",
        "sysContact": "—",
        "sysLocation": "—",
        "ifNumber": "—",
        "device_type": "unknown",
        "uptime_seconds": 0,
    }

    alive = ping_host(ip, timeout=min(timeout, 1.5))
    if not alive:
        return device

    device["status"]   = "Actif"
    device["hostname"] = resolve_hostname(ip)

    if SNMP_AVAILABLE:
        snmp_data = snmp_get_bulk(ip, community, OIDS,
                                   version=version, timeout=timeout)
        device.update(snmp_data)
        raw_up = device.get("sysUpTime", "—")
        device["uptime_seconds"] = uptime_to_seconds(raw_up)
        device["sysUpTime"]      = format_uptime(raw_up)
        device["device_type"]    = detect_device_type(
            device.get("sysDescr", "")
        )

    return device


# ── Moteur de scan multi-threadé ──────────────────────────────────────────────

class ScanEngine:
    """
    Scanne une plage IP avec un pool de threads.
    Résultats disponibles via la liste self.results (thread-safe).
    """

    def __init__(self):
        self._stop_event = threading.Event()
        self.results: list  = []
        self.progress: int  = 0
        self.total: int     = 0
        self.running: bool  = False
        self._lock = threading.Lock()

    def stop(self):
        self._stop_event.set()

    def scan(self, subnet: str, community: str, version: int,
             timeout: int, max_threads: int,
             on_device=None, on_progress=None):
        """
        Lance le scan. Callbacks optionnels :
        - on_device(device_dict)  : appelé dès qu'un hôte actif est trouvé
        - on_progress(done, total): appelé après chaque hôte traité
        """
        self._stop_event.clear()
        self.results.clear()
        self.progress = 0

        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as e:
            raise ValueError(f"Plage IP invalide : {e}")

        hosts = list(network.hosts())
        self.total   = len(hosts)
        self.running = True

        semaphore = threading.Semaphore(max_threads)
        threads   = []
        done_lock = threading.Lock()
        done_count = [0]

        def _scan_one(ip_obj):
            if self._stop_event.is_set():
                return
            ip = str(ip_obj)
            with semaphore:
                if self._stop_event.is_set():
                    return
                device = scan_host_full(ip, community, version, timeout)
                if device["status"] == "Actif":
                    with self._lock:
                        self.results.append(device)
                    if on_device:
                        on_device(device)
                with done_lock:
                    done_count[0] += 1
                    self.progress = done_count[0]
                if on_progress:
                    on_progress(done_count[0], self.total)

        for ip_obj in hosts:
            if self._stop_event.is_set():
                break
            t = threading.Thread(target=_scan_one,
                                  args=(ip_obj,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.running = False


# ── Base de données ───────────────────────────────────────────────────────────

class Database:
    DB_PATH = "netscanpro.db"

    def __init__(self, path: str = None):
        self.path = path or self.DB_PATH
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.Lock()
        self._create_tables()

    def _create_tables(self):
        with self._lock:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    date         TEXT,
                    subnet       TEXT,
                    community    TEXT,
                    total_hosts  INTEGER,
                    active_hosts INTEGER,
                    snmp_hosts   INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS devices (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id      INTEGER,
                    ip           TEXT,
                    hostname     TEXT,
                    sys_name     TEXT,
                    sys_descr    TEXT,
                    sys_location TEXT,
                    sys_contact  TEXT,
                    sys_uptime   TEXT,
                    uptime_sec   INTEGER DEFAULT 0,
                    device_type  TEXT,
                    if_number    TEXT,
                    status       TEXT
                );
            """)
            self.conn.commit()

    def save_scan(self, subnet: str, community: str,
                  devices: list) -> int:
        with self._lock:
            now    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            active = [d for d in devices if d["status"] == "Actif"]
            snmp_r = sum(1 for d in active if d.get("sysName", "—") != "—")
            cur = self.conn.execute(
                "INSERT INTO scans(date,subnet,community,total_hosts,"
                "active_hosts,snmp_hosts) VALUES(?,?,?,?,?,?)",
                (now, subnet, community, len(devices), len(active), snmp_r)
            )
            scan_id = cur.lastrowid
            for d in devices:
                self.conn.execute("""
                    INSERT INTO devices(scan_id,ip,hostname,sys_name,sys_descr,
                        sys_location,sys_contact,sys_uptime,uptime_sec,
                        device_type,if_number,status)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    scan_id,
                    d.get("ip", ""),
                    d.get("hostname", "—"),
                    d.get("sysName", "—"),
                    d.get("sysDescr", "—"),
                    d.get("sysLocation", "—"),
                    d.get("sysContact", "—"),
                    d.get("sysUpTime", "—"),
                    d.get("uptime_seconds", 0),
                    d.get("device_type", "unknown"),
                    d.get("ifNumber", "—"),
                    d.get("status", "Inactif"),
                ))
            self.conn.commit()
            return scan_id

    def get_scans(self) -> list:
        with self._lock:
            cur = self.conn.execute(
                "SELECT id,date,subnet,active_hosts,total_hosts,snmp_hosts"
                " FROM scans ORDER BY id DESC LIMIT 50"
            )
            return cur.fetchall()

    def get_devices_for_scan(self, scan_id: int) -> list:
        with self._lock:
            cur = self.conn.execute(
                "SELECT ip,hostname,sys_name,sys_descr,sys_location,"
                "sys_contact,sys_uptime,device_type,if_number,status"
                " FROM devices WHERE scan_id=? ORDER BY ip",
                (scan_id,)
            )
            cols = ["ip","hostname","sysName","sysDescr","sysLocation",
                    "sysContact","sysUpTime","device_type","ifNumber","status"]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def delete_scan(self, scan_id: int):
        with self._lock:
            self.conn.execute(
                "DELETE FROM devices WHERE scan_id=?", (scan_id,))
            self.conn.execute(
                "DELETE FROM scans WHERE id=?", (scan_id,))
            self.conn.commit()

    def close(self):
        self.conn.close()


# ── Export CSV ────────────────────────────────────────────────────────────────

def devices_to_csv(devices: list) -> str:
    """Retourne le contenu CSV des devices sous forme de chaîne."""
    fields = ["ip","hostname","sysName","sysDescr","sysLocation",
              "sysContact","sysUpTime","ifNumber","device_type","status"]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for d in devices:
        writer.writerow({k: d.get(k, "—") for k in fields})
    return output.getvalue()


# ── Export PDF ────────────────────────────────────────────────────────────────

def devices_to_pdf(devices: list, subnet: str) -> bytes:
    """Génère un PDF et retourne les bytes."""
    if not REPORTLAB_AVAILABLE:
        return b""
    buf = io.BytesIO()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    title_s = ParagraphStyle("T", parent=styles["Title"],
                              fontSize=20, spaceAfter=6,
                              textColor=rl_colors.HexColor("#1A202C"))
    sub_s   = ParagraphStyle("S", parent=styles["Normal"],
                              fontSize=11, spaceAfter=20,
                              textColor=rl_colors.HexColor("#718096"))
    h2_s    = ParagraphStyle("H2", parent=styles["Heading2"],
                              fontSize=13, spaceBefore=8, spaceAfter=8,
                              textColor=rl_colors.HexColor("#1A202C"))

    story.append(Paragraph("NetScan Pro — Rapport d'inventaire réseau", title_s))
    story.append(Paragraph(f"Plage : {subnet} | Généré le {now}", sub_s))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=rl_colors.HexColor("#E2E8F0"), spaceAfter=16))

    active   = [d for d in devices if d.get("status") == "Actif"]
    inactive = [d for d in devices if d.get("status") != "Actif"]
    snmp_r   = sum(1 for d in active if d.get("sysName", "—") != "—")

    # Résumé
    summary = [
        ["Hôtes scannés", "Hôtes actifs", "Inactifs", "SNMP répondants"],
        [str(len(devices)), str(len(active)), str(len(inactive)), str(snmp_r)]
    ]
    st = Table(summary, colWidths=[4*cm]*4)
    st.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,0), rl_colors.HexColor("#1A202C")),
        ("TEXTCOLOR",  (0,0),(-1,0), rl_colors.white),
        ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0),(-1,-1), 10),
        ("ALIGN",      (0,0),(-1,-1), "CENTER"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),
         [rl_colors.HexColor("#F8F9FA"), rl_colors.white]),
        ("GRID", (0,0),(-1,-1), 0.5, rl_colors.HexColor("#E2E8F0")),
        ("TOPPADDING",    (0,0),(-1,-1), 8),
        ("BOTTOMPADDING", (0,0),(-1,-1), 8),
    ]))
    story.append(st)
    story.append(Spacer(1, 20))

    if active:
        story.append(Paragraph("Équipements actifs", h2_s))
        rows = [["IP","sysName","Type","Uptime","Localisation","Interfaces"]]
        for d in sorted(active,
                        key=lambda x: ipaddress.ip_address(x["ip"])):
            dtype = d.get("device_type","unknown")
            rows.append([
                d["ip"],
                d.get("sysName","—")[:25],
                DEVICE_TYPES.get(dtype,{}).get("label","Inconnu"),
                d.get("sysUpTime","—"),
                d.get("sysLocation","—")[:20],
                d.get("ifNumber","—"),
            ])
        mt = Table(rows, colWidths=[3*cm,4.5*cm,2.5*cm,2.5*cm,3.5*cm,2*cm],
                   repeatRows=1)
        mt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0), rl_colors.HexColor("#1D9E75")),
            ("TEXTCOLOR",  (0,0),(-1,0), rl_colors.white),
            ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0),(-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),
             [rl_colors.white, rl_colors.HexColor("#F7FAFC")]),
            ("GRID",(0,0),(-1,-1),0.3, rl_colors.HexColor("#E2E8F0")),
            ("TOPPADDING",    (0,0),(-1,-1), 6),
            ("BOTTOMPADDING", (0,0),(-1,-1), 6),
            ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ]))
        story.append(mt)

    doc.build(story)
    buf.seek(0)
    return buf.read()
