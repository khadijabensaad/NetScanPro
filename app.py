"""
NetScan Pro — Interface Streamlit
Application web de supervision réseau SNMP
"""

import streamlit as st
import threading
import time
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import math
import ipaddress
import datetime

from core import (
    ScanEngine, Database, DEVICE_TYPES, OIDS,
    SNMP_AVAILABLE, PING_AVAILABLE, REPORTLAB_AVAILABLE,
    devices_to_csv, devices_to_pdf,
)

# ── Configuration de la page ──────────────────────────────────────────────────

st.set_page_config(
    page_title="NetScan Pro",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS personnalisé ──────────────────────────────────────────────────────────

st.markdown("""
<style>
  /* Couleurs globales */
  :root {
    --green:      #1D9E75;
    --green-dk:   #0F6E56;
    --dark:       #1A202C;
    --muted:      #718096;
    --border:     #E2E8F0;
    --bg:         #F8F9FA;
    --surface:    #FFFFFF;
    --danger:     #E24B4A;
    --warning:    #BA7517;
    --accent:     #185FA5;
  }

  /* Header */
  .nsp-header {
    background: linear-gradient(135deg, #1A202C 0%, #2D3748 100%);
    border-radius: 16px;
    padding: 28px 36px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 4px 24px rgba(0,0,0,0.15);
  }
  .nsp-logo { font-size: 2.4rem; font-weight: 800; color: #1D9E75; letter-spacing: -1px; }
  .nsp-sub  { color: #A0AEC0; font-size: 1rem; margin-top: 4px; }
  .nsp-badge {
    background: rgba(29,158,117,0.15);
    border: 1px solid rgba(29,158,117,0.4);
    color: #1D9E75;
    padding: 6px 16px;
    border-radius: 999px;
    font-size: 0.85rem;
    font-weight: 500;
  }

  /* Cartes de statistiques */
  .stat-card {
    background: white;
    border-radius: 12px;
    padding: 20px 24px;
    text-align: center;
    border: 1px solid #E2E8F0;
    box-shadow: 0 1px 8px rgba(0,0,0,0.05);
    transition: transform 0.2s;
  }
  .stat-card:hover { transform: translateY(-2px); }
  .stat-val   { font-size: 2.4rem; font-weight: 800; line-height: 1.1; }
  .stat-label { color: #718096; font-size: 0.85rem; margin-top: 4px; font-weight: 500; }
  .stat-green { color: #1D9E75; }
  .stat-red   { color: #E24B4A; }
  .stat-blue  { color: #185FA5; }
  .stat-gray  { color: #4A5568; }

  /* Tableau */
  .device-row {
    background: white;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 8px;
    border: 1px solid #E2E8F0;
    display: flex;
    align-items: center;
    gap: 16px;
    transition: box-shadow 0.15s;
  }
  .device-row:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.08); }

  /* Badge statut */
  .badge-active   { background:#E1F5EE; color:#085041; padding:3px 12px;
                    border-radius:999px; font-size:0.8rem; font-weight:600; }
  .badge-inactive { background:#F3F4F6; color:#6B7280; padding:3px 12px;
                    border-radius:999px; font-size:0.8rem; font-weight:600; }
  .badge-warning  { background:#FAEEDA; color:#633806; padding:3px 12px;
                    border-radius:999px; font-size:0.8rem; font-weight:600; }

  /* Carte équipement détail */
  .detail-card {
    background: linear-gradient(135deg, #f8f9fa 0%, #ffffff 100%);
    border-radius: 14px;
    padding: 24px;
    border: 1px solid #E2E8F0;
    box-shadow: 0 2px 12px rgba(0,0,0,0.06);
  }
  .detail-field { margin-bottom: 14px; }
  .detail-label { font-size: 0.75rem; color: #718096; font-weight: 600;
                  text-transform: uppercase; letter-spacing: 0.05em; }
  .detail-value { font-size: 1rem; color: #1A202C; font-weight: 500; margin-top: 2px; }

  /* Section titre */
  .section-title {
    font-size: 1.1rem; font-weight: 700; color: #1A202C;
    border-left: 4px solid #1D9E75;
    padding-left: 12px; margin: 20px 0 12px;
  }

  /* Alerte info */
  .info-box {
    background: #EBF8F5; border: 1px solid #9DECDA;
    border-radius: 10px; padding: 14px 18px;
    color: #085041; font-size: 0.9rem; margin-bottom: 12px;
  }
  .warn-box {
    background: #FEFCE8; border: 1px solid #FDE68A;
    border-radius: 10px; padding: 14px 18px;
    color: #78350F; font-size: 0.9rem; margin-bottom: 12px;
  }

  /* Sidebar */
  [data-testid="stSidebar"] { background: #1A202C !important; }
  [data-testid="stSidebar"] * { color: #E2E8F0 !important; }
  [data-testid="stSidebar"] .stTextInput input,
  [data-testid="stSidebar"] .stSelectbox select,
  [data-testid="stSidebar"] .stNumberInput input {
    background: #2D3748 !important;
    color: white !important;
    border-color: #4A5568 !important;
    border-radius: 8px !important;
  }

  /* Boutons */
  .stButton > button {
    border-radius: 10px !important;
    font-weight: 600 !important;
    transition: all 0.2s !important;
  }

  /* Tabs */
  .stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background: #F8F9FA;
    padding: 6px;
    border-radius: 12px;
  }
  .stTabs [data-baseweb="tab"] {
    border-radius: 8px !important;
    font-weight: 600 !important;
    color: #718096 !important;
  }
  .stTabs [aria-selected="true"] {
    background: white !important;
    color: #1A202C !important;
    box-shadow: 0 1px 6px rgba(0,0,0,0.08) !important;
  }

  /* Progress */
  .progress-container {
    background: #E2E8F0; border-radius: 999px;
    height: 10px; overflow: hidden; margin: 8px 0;
  }
  .progress-fill {
    background: linear-gradient(90deg, #1D9E75, #0F6E56);
    height: 100%; border-radius: 999px;
    transition: width 0.3s ease;
  }

  /* Responsive tweaks */
  .block-container { padding-top: 1.5rem !important; }
</style>
""", unsafe_allow_html=True)


# ── Session state ─────────────────────────────────────────────────────────────

def init_state():
    defaults = {
        "devices":        [],
        "scan_running":   False,
        "scan_done":      False,
        "scan_progress":  0,
        "scan_total":     0,
        "scan_engine":    None,
        "db":             Database(),
        "selected_ip":    None,
        "last_subnet":    "",
        "scan_thread":    None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style='text-align:center; padding: 20px 0 10px;'>
      <div style='font-size:2rem; font-weight:800; color:#1D9E75;'>⬡ NetScan Pro</div>
      <div style='color:#A0AEC0; font-size:0.85rem; margin-top:4px;'>
        Supervision réseau SNMP
      </div>
    </div>
    <hr style='border-color:#2D3748; margin:12px 0;'>
    """, unsafe_allow_html=True)

    st.markdown("<div style='color:#A0AEC0; font-size:0.75rem; font-weight:700; letter-spacing:0.08em; margin-bottom:8px;'>PARAMÈTRES DU SCAN</div>", unsafe_allow_html=True)

    subnet    = st.text_input("Plage IP (CIDR)", value="192.168.1.0/24",
                               help="Exemple : 192.168.1.0/24")
    community = st.text_input("Communauté SNMP", value="public",
                               help="Communauté SNMP (lecture seule : 'public')")
    version   = st.selectbox("Version SNMP", ["v2c", "v1"],
                              help="v2c recommandé pour les équipements récents")
    timeout   = st.slider("Timeout (sec)", 1, 10, 2)
    threads   = st.slider("Threads simultanés", 5, 50, 20)

    st.markdown("<hr style='border-color:#2D3748; margin:16px 0;'>", unsafe_allow_html=True)

    # Validation plage
    valid_subnet = True
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        n_hosts = net.num_addresses - 2
        st.markdown(f"<div style='color:#68D391; font-size:0.8rem;'>✓ {n_hosts} adresses à scanner</div>",
                    unsafe_allow_html=True)
    except ValueError:
        valid_subnet = False
        st.markdown("<div style='color:#FC8181; font-size:0.8rem;'>✗ Plage IP invalide</div>",
                    unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_a, col_b = st.columns(2)
    with col_a:
        btn_scan = st.button(
            "▶ Scanner",
            type="primary",
            disabled=(st.session_state.scan_running or not valid_subnet),
            use_container_width=True
        )
    with col_b:
        btn_stop = st.button(
            "■ Stop",
            disabled=not st.session_state.scan_running,
            use_container_width=True
        )

    st.markdown("<hr style='border-color:#2D3748; margin:16px 0;'>", unsafe_allow_html=True)

    # Statut dépendances
    st.markdown("<div style='color:#A0AEC0; font-size:0.75rem; font-weight:700; letter-spacing:0.08em; margin-bottom:8px;'>DÉPENDANCES</div>", unsafe_allow_html=True)
    dep_items = [
        ("pysnmp",     SNMP_AVAILABLE),
        ("ping3",      PING_AVAILABLE),
        ("reportlab",  REPORTLAB_AVAILABLE),
    ]
    for name, ok in dep_items:
        color = "#68D391" if ok else "#FC8181"
        icon  = "✓" if ok else "✗"
        st.markdown(f"<div style='color:{color}; font-size:0.82rem;'>{icon} {name}</div>",
                    unsafe_allow_html=True)

    # Exports
    if st.session_state.devices:
        st.markdown("<hr style='border-color:#2D3748; margin:16px 0;'>", unsafe_allow_html=True)
        st.markdown("<div style='color:#A0AEC0; font-size:0.75rem; font-weight:700; letter-spacing:0.08em; margin-bottom:8px;'>EXPORTER</div>", unsafe_allow_html=True)

        csv_data = devices_to_csv(st.session_state.devices)
        st.download_button(
            label="⬇ CSV",
            data=csv_data,
            file_name=f"netscan_{datetime.date.today()}.csv",
            mime="text/csv",
            use_container_width=True
        )

        if REPORTLAB_AVAILABLE:
            pdf_data = devices_to_pdf(st.session_state.devices, subnet)
            st.download_button(
                label="⬇ PDF",
                data=pdf_data,
                file_name=f"netscan_{datetime.date.today()}.pdf",
                mime="application/pdf",
                use_container_width=True
            )


# ── Logique scan ──────────────────────────────────────────────────────────────

if btn_scan and valid_subnet and not st.session_state.scan_running:
    st.session_state.devices      = []
    st.session_state.scan_running = True
    st.session_state.scan_done    = False
    st.session_state.scan_progress = 0
    st.session_state.last_subnet  = subnet

    engine = ScanEngine()
    st.session_state.scan_engine = engine

    ver_int = 2 if version == "v2c" else 1

    def run_scan():
        engine.scan(
            subnet=subnet,
            community=community,
            version=ver_int,
            timeout=timeout,
            max_threads=threads,
        )
        st.session_state.devices      = engine.results.copy()
        st.session_state.scan_running = False
        st.session_state.scan_done    = True
        # Sauvegarde DB
        if engine.results:
            st.session_state.db.save_scan(subnet, community, engine.results)

    t = threading.Thread(target=run_scan, daemon=True)
    st.session_state.scan_thread = t
    t.start()

if btn_stop and st.session_state.scan_running:
    if st.session_state.scan_engine:
        st.session_state.scan_engine.stop()


# ── Header principal ──────────────────────────────────────────────────────────

devices  = st.session_state.devices
active   = [d for d in devices if d.get("status") == "Actif"]
inactive = [d for d in devices if d.get("status") != "Actif"]
snmp_r   = sum(1 for d in active if d.get("sysName", "—") != "—")

if st.session_state.scan_running:
    status_html = "<span class='nsp-badge' style='background:rgba(186,117,23,0.15);border-color:rgba(186,117,23,0.4);color:#BA7517;'>⏳ Scan en cours…</span>"
elif st.session_state.scan_done:
    status_html = f"<span class='nsp-badge'>✓ Terminé — {len(active)} actifs</span>"
else:
    status_html = "<span class='nsp-badge' style='background:rgba(113,128,150,0.15);border-color:rgba(113,128,150,0.4);color:#718096;'>Prêt</span>"

st.markdown(f"""
<div class="nsp-header">
  <div>
    <div class="nsp-logo">⬡ NetScan Pro</div>
    <div class="nsp-sub">Cartographie & inventaire réseau SNMP — {st.session_state.get('last_subnet') or subnet}</div>
  </div>
  {status_html}
</div>
""", unsafe_allow_html=True)


# ── Barre de progression ──────────────────────────────────────────────────────

if st.session_state.scan_running:
    engine = st.session_state.scan_engine
    if engine:
        done  = engine.progress
        total = engine.total or 1
        pct   = int(done / total * 100)
        st.markdown(f"""
        <div style='margin-bottom:16px;'>
          <div style='display:flex; justify-content:space-between; margin-bottom:4px;'>
            <span style='font-size:0.85rem; color:#718096;'>Progression du scan</span>
            <span style='font-size:0.85rem; font-weight:600; color:#1D9E75;'>{done}/{total} — {pct}%</span>
          </div>
          <div class='progress-container'>
            <div class='progress-fill' style='width:{pct}%;'></div>
          </div>
        </div>
        """, unsafe_allow_html=True)
    time.sleep(0.4)
    st.rerun()


# ── Cartes statistiques ───────────────────────────────────────────────────────

c1, c2, c3, c4 = st.columns(4)
stats = [
    (c1, len(active) + len(inactive), "Hôtes scannés", "stat-gray"),
    (c2, len(active),                 "Actifs",          "stat-green"),
    (c3, len(inactive),               "Inactifs",         "stat-red"),
    (c4, snmp_r,                      "SNMP répondants",  "stat-blue"),
]
for col, val, label, cls in stats:
    col.markdown(f"""
    <div class='stat-card'>
      <div class='stat-val {cls}'>{val}</div>
      <div class='stat-label'>{label}</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# ── Onglets principaux ────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📋 Inventaire",
    "🗺️ Carte réseau",
    "📊 Statistiques",
    "🕒 Historique",
    "ℹ️ À propos",
])


# ══════════════════════════════════════════════════════════════════════════════
# ONGLET 1 — INVENTAIRE
# ══════════════════════════════════════════════════════════════════════════════

with tab1:
    if not devices:
        st.markdown("""
        <div class='info-box'>
          🔍 Lancez un scan depuis le panneau gauche pour découvrir les équipements de votre réseau.
        </div>
        """, unsafe_allow_html=True)
    else:
        # Filtres
        fc1, fc2, fc3 = st.columns([3, 2, 2])
        with fc1:
            search = st.text_input("🔍 Rechercher", placeholder="IP, nom, localisation…",
                                    label_visibility="collapsed")
        with fc2:
            type_f = st.selectbox("Type", ["Tous"] + [v["label"] for v in DEVICE_TYPES.values()],
                                   label_visibility="collapsed")
        with fc3:
            status_f = st.selectbox("Statut", ["Tous", "Actif", "Inactif"],
                                     label_visibility="collapsed")

        # Filtrage
        filtered = devices
        if search:
            q = search.lower()
            filtered = [d for d in filtered if any(
                q in str(d.get(k, "")).lower()
                for k in ["ip","hostname","sysName","sysDescr","sysLocation"]
            )]
        if type_f != "Tous":
            filtered = [d for d in filtered
                        if DEVICE_TYPES.get(d.get("device_type","unknown"),{}).get("label") == type_f]
        if status_f != "Tous":
            filtered = [d for d in filtered if d.get("status") == status_f]

        st.markdown(f"<div style='color:#718096; font-size:0.85rem; margin-bottom:12px;'>{len(filtered)} équipement(s) affiché(s)</div>",
                    unsafe_allow_html=True)

        # Tableau avec pandas + st.dataframe stylisé
        if filtered:
            rows = []
            for d in sorted(filtered, key=lambda x: ipaddress.ip_address(x["ip"])):
                dtype = d.get("device_type","unknown")
                info  = DEVICE_TYPES.get(dtype, DEVICE_TYPES["unknown"])
                rows.append({
                    "Statut":       "🟢 Actif" if d["status"]=="Actif" else "🔴 Inactif",
                    "Adresse IP":   d["ip"],
                    "Nom DNS":      d.get("hostname","—"),
                    "sysName":      d.get("sysName","—"),
                    "Type":         f"{info['icon']} {info['label']}",
                    "Uptime":       d.get("sysUpTime","—"),
                    "Localisation": d.get("sysLocation","—"),
                    "Interfaces":   d.get("ifNumber","—"),
                })

            df = pd.DataFrame(rows)
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Statut":       st.column_config.TextColumn("Statut", width=90),
                    "Adresse IP":   st.column_config.TextColumn("Adresse IP", width=120),
                    "Nom DNS":      st.column_config.TextColumn("Nom DNS", width=160),
                    "sysName":      st.column_config.TextColumn("sysName", width=160),
                    "Type":         st.column_config.TextColumn("Type", width=120),
                    "Uptime":       st.column_config.TextColumn("Uptime", width=110),
                    "Localisation": st.column_config.TextColumn("Localisation", width=140),
                    "Interfaces":   st.column_config.TextColumn("Ifaces", width=70),
                }
            )

            # Panneau détail
            st.markdown("<div class='section-title'>Détail d'un équipement</div>", unsafe_allow_html=True)
            ips = [d["ip"] for d in sorted(filtered, key=lambda x: ipaddress.ip_address(x["ip"]))]
            selected_ip = st.selectbox("Sélectionner un équipement", ips,
                                        label_visibility="collapsed")
            sel = next((d for d in devices if d["ip"] == selected_ip), None)

            if sel:
                dtype = sel.get("device_type","unknown")
                info  = DEVICE_TYPES.get(dtype, DEVICE_TYPES["unknown"])
                d1, d2 = st.columns([1, 2])
                with d1:
                    st.markdown(f"""
                    <div class='detail-card' style='text-align:center;'>
                      <div style='font-size:3rem;'>{info['icon']}</div>
                      <div style='font-size:1.3rem; font-weight:700; color:{info['color']}; margin:8px 0;'>{info['label']}</div>
                      <div style='font-size:1.1rem; font-weight:600; color:#1A202C;'>{sel['ip']}</div>
                      <div style='margin-top:10px;'>
                        <span class='badge-{"active" if sel["status"]=="Actif" else "inactive"}'>{sel["status"]}</span>
                      </div>
                    </div>
                    """, unsafe_allow_html=True)
                with d2:
                    fields = [
                        ("sysName",     sel.get("sysName","—")),
                        ("Nom DNS",     sel.get("hostname","—")),
                        ("sysDescr",    sel.get("sysDescr","—")[:80]),
                        ("sysLocation", sel.get("sysLocation","—")),
                        ("sysContact",  sel.get("sysContact","—")),
                        ("sysUpTime",   sel.get("sysUpTime","—")),
                        ("Interfaces",  sel.get("ifNumber","—")),
                    ]
                    cols = st.columns(2)
                    for i, (label, value) in enumerate(fields):
                        with cols[i % 2]:
                            st.markdown(f"""
                            <div class='detail-field'>
                              <div class='detail-label'>{label}</div>
                              <div class='detail-value'>{value}</div>
                            </div>
                            """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# ONGLET 2 — CARTE RÉSEAU
# ══════════════════════════════════════════════════════════════════════════════

with tab2:
    if not active:
        st.markdown("<div class='info-box'>Aucun équipement actif à afficher. Lancez un scan.</div>",
                    unsafe_allow_html=True)
    else:
        st.markdown("<div style='color:#718096; font-size:0.9rem; margin-bottom:16px;'>Topologie en étoile — les équipements actifs sont disposés autour du nœud central (passerelle supposée).</div>",
                    unsafe_allow_html=True)

        # Nœud central = .1 ou premier
        gateway = next((d for d in active if d["ip"].endswith(".1")), active[0])
        others  = [d for d in active if d["ip"] != gateway["ip"]]

        # Positions en cercle
        nodes_x, nodes_y, labels, colors_list, sizes, texts, icons = [], [], [], [], [], [], []
        edge_x, edge_y = [], []
        radius = 2.5

        def add_node(d, x, y, is_gw=False):
            dtype = d.get("device_type","unknown")
            info  = DEVICE_TYPES.get(dtype, DEVICE_TYPES["unknown"])
            nodes_x.append(x)
            nodes_y.append(y)
            name  = d.get("sysName","—")
            short = name[:14] + "…" if len(name) > 14 else name
            labels.append(f"{d['ip']}<br><b>{short}</b>")
            colors_list.append(info["color"])
            sizes.append(52 if is_gw else 38)
            texts.append(
                f"IP: {d['ip']}<br>"
                f"Type: {info['label']}<br>"
                f"sysName: {d.get('sysName','—')}<br>"
                f"Uptime: {d.get('sysUpTime','—')}<br>"
                f"Localisation: {d.get('sysLocation','—')}<br>"
                f"Interfaces: {d.get('ifNumber','—')}"
            )
            icons.append(info["icon"])

        # Passerelle au centre
        cx, cy = 0, 0
        add_node(gateway, cx, cy, is_gw=True)

        # Autres en cercle
        for i, d in enumerate(others):
            angle = 2 * math.pi * i / max(len(others), 1)
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)
            add_node(d, x, y)
            # Arête
            edge_x += [cx, x, None]
            edge_y += [cy, y, None]

        fig = go.Figure()

        # Arêtes
        fig.add_trace(go.Scatter(
            x=edge_x, y=edge_y, mode="lines",
            line=dict(color="#CBD5E0", width=1.5, dash="dot"),
            hoverinfo="none", showlegend=False
        ))

        # Nœuds
        fig.add_trace(go.Scatter(
            x=nodes_x, y=nodes_y,
            mode="markers+text",
            text=[i["icon"] for i in [DEVICE_TYPES.get(d.get("device_type","unknown"), DEVICE_TYPES["unknown"]) for d in [gateway]+others]],
            textposition="middle center",
            textfont=dict(size=16),
            hovertext=texts,
            hoverinfo="text",
            marker=dict(
                color=colors_list,
                size=sizes,
                line=dict(color="white", width=3),
                opacity=0.92,
            ),
            showlegend=False
        ))

        # Labels IP sous les nœuds
        fig.add_trace(go.Scatter(
            x=nodes_x,
            y=[y - 0.42 for y in nodes_y],
            mode="text",
            text=[d["ip"].split(".")[-1] + "<br>" +
                  (d.get("sysName","")[:12] if d.get("sysName","—") != "—" else "")
                  for d in [gateway]+others],
            textfont=dict(size=10, color="#4A5568"),
            hoverinfo="none",
            showlegend=False
        ))

        fig.update_layout(
            height=520,
            margin=dict(l=20, r=20, t=20, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#F8F9FA",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False,
                       scaleanchor="x", scaleratio=1),
            hoverlabel=dict(bgcolor="white", bordercolor="#E2E8F0",
                            font=dict(size=12, color="#1A202C")),
        )

        st.plotly_chart(fig, use_container_width=True)

        # Légende
        leg_cols = st.columns(len(DEVICE_TYPES) - 1)
        for i, (key, info) in enumerate(DEVICE_TYPES.items()):
            if key == "unknown":
                continue
            count = sum(1 for d in active if d.get("device_type") == key)
            if i < len(leg_cols):
                leg_cols[i].markdown(f"""
                <div style='text-align:center; padding:8px;
                     background:white; border-radius:8px;
                     border:1px solid #E2E8F0;'>
                  <span style='font-size:1.3rem;'>{info['icon']}</span><br>
                  <span style='font-size:0.75rem; color:#718096;'>{info['label']}</span><br>
                  <span style='font-size:1rem; font-weight:700; color:{info['color']};'>{count}</span>
                </div>
                """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# ONGLET 3 — STATISTIQUES
# ══════════════════════════════════════════════════════════════════════════════

with tab3:
    if not devices:
        st.markdown("<div class='info-box'>Aucune donnée disponible. Lancez un scan.</div>",
                    unsafe_allow_html=True)
    else:
        sc1, sc2 = st.columns(2)

        # Graphe 1 — Répartition par type
        with sc1:
            st.markdown("<div class='section-title'>Répartition par type d'équipement</div>",
                        unsafe_allow_html=True)
            type_counts = {}
            for d in active:
                dtype = d.get("device_type","unknown")
                label = DEVICE_TYPES.get(dtype, DEVICE_TYPES["unknown"])["label"]
                type_counts[label] = type_counts.get(label, 0) + 1

            if type_counts:
                fig_pie = go.Figure(go.Pie(
                    labels=list(type_counts.keys()),
                    values=list(type_counts.values()),
                    hole=0.45,
                    marker=dict(colors=[
                        DEVICE_TYPES.get(k, DEVICE_TYPES["unknown"])["color"]
                        for k in [next((key for key,v in DEVICE_TYPES.items() if v["label"]==lbl), "unknown")
                                  for lbl in type_counts.keys()]
                    ], line=dict(color="white", width=2)),
                    textinfo="label+percent",
                    hovertemplate="<b>%{label}</b><br>%{value} équipement(s)<extra></extra>"
                ))
                fig_pie.update_layout(
                    height=320, margin=dict(l=0,r=0,t=0,b=0),
                    paper_bgcolor="rgba(0,0,0,0)",
                    showlegend=False,
                    annotations=[dict(text=f"<b>{len(active)}</b><br>actifs",
                                      x=0.5, y=0.5, font_size=14,
                                      showarrow=False)]
                )
                st.plotly_chart(fig_pie, use_container_width=True)

        # Graphe 2 — Statut actif/inactif
        with sc2:
            st.markdown("<div class='section-title'>Hôtes actifs vs inactifs</div>",
                        unsafe_allow_html=True)
            fig_bar = go.Figure(go.Bar(
                x=["Actifs", "Inactifs", "SNMP OK"],
                y=[len(active), len(inactive), snmp_r],
                marker_color=["#1D9E75", "#E24B4A", "#185FA5"],
                text=[len(active), len(inactive), snmp_r],
                textposition="outside",
            ))
            fig_bar.update_layout(
                height=320, margin=dict(l=0,r=20,t=20,b=0),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                yaxis=dict(gridcolor="#F3F4F6"),
                showlegend=False,
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        # Graphe 3 — Top uptimes
        st.markdown("<div class='section-title'>Top équipements par uptime</div>",
                    unsafe_allow_html=True)
        uptime_devs = sorted(
            [d for d in active if d.get("uptime_seconds",0) > 0],
            key=lambda x: x.get("uptime_seconds",0), reverse=True
        )[:10]

        if uptime_devs:
            names = [d.get("sysName","—") if d.get("sysName","—") != "—"
                     else d["ip"] for d in uptime_devs]
            uptimes = [d.get("uptime_seconds",0) / 86400 for d in uptime_devs]
            labels_up = [d.get("sysUpTime","—") for d in uptime_devs]

            fig_up = go.Figure(go.Bar(
                x=names, y=uptimes,
                marker_color="#1D9E75",
                text=labels_up,
                textposition="outside",
                hovertemplate="<b>%{x}</b><br>%{text}<extra></extra>"
            ))
            fig_up.update_layout(
                height=300,
                margin=dict(l=0,r=0,t=10,b=0),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                yaxis=dict(title="Jours", gridcolor="#F3F4F6"),
                xaxis=dict(tickangle=-20),
                showlegend=False,
            )
            st.plotly_chart(fig_up, use_container_width=True)
        else:
            st.markdown("<div class='warn-box'>⚠️ Aucune donnée d'uptime disponible (SNMP non répondant ou non configuré).</div>",
                        unsafe_allow_html=True)

        # Tableau résumé SNMP
        st.markdown("<div class='section-title'>Résumé des OIDs collectés</div>",
                    unsafe_allow_html=True)
        oid_stats = {}
        for oid_name in OIDS.keys():
            filled = sum(1 for d in active if d.get(oid_name,"—") != "—")
            oid_stats[oid_name] = filled

        oid_df = pd.DataFrame([
            {"OID": k, "OID complet": OIDS[k],
             "Répondants": v, "Taux": f"{v/max(len(active),1)*100:.0f}%"}
            for k,v in oid_stats.items()
        ])
        st.dataframe(oid_df, use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════════════════════
# ONGLET 4 — HISTORIQUE
# ══════════════════════════════════════════════════════════════════════════════

with tab4:
    scans = st.session_state.db.get_scans()

    if not scans:
        st.markdown("<div class='info-box'>Aucun historique disponible.</div>",
                    unsafe_allow_html=True)
    else:
        # Graphe évolution
        if len(scans) >= 2:
            st.markdown("<div class='section-title'>Évolution des hôtes actifs</div>",
                        unsafe_allow_html=True)
            hist_df = pd.DataFrame(
                [(row[1], row[3]) for row in reversed(scans)],
                columns=["Date","Actifs"]
            )
            fig_hist = px.line(
                hist_df, x="Date", y="Actifs",
                markers=True,
                color_discrete_sequence=["#1D9E75"]
            )
            fig_hist.update_layout(
                height=220, margin=dict(l=0,r=0,t=10,b=0),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                yaxis=dict(gridcolor="#F3F4F6"),
            )
            st.plotly_chart(fig_hist, use_container_width=True)

        # Tableau historique
        st.markdown("<div class='section-title'>Scans précédents</div>",
                    unsafe_allow_html=True)
        hist_rows = []
        for row in scans:
            hist_rows.append({
                "ID": row[0], "Date": row[1], "Plage IP": row[2],
                "Actifs": row[3], "Total": row[4], "SNMP": row[5]
            })
        hist_df2 = pd.DataFrame(hist_rows)
        st.dataframe(hist_df2, use_container_width=True, hide_index=True)

        # Recharger un scan
        st.markdown("<div class='section-title'>Recharger un scan</div>",
                    unsafe_allow_html=True)
        scan_ids = [row[0] for row in scans]
        chosen   = st.selectbox("Scan ID", scan_ids, label_visibility="collapsed")
        if st.button("📂 Charger ce scan"):
            loaded = st.session_state.db.get_devices_for_scan(chosen)
            st.session_state.devices   = loaded
            st.session_state.scan_done = True
            st.success(f"✓ {len(loaded)} équipements chargés depuis le scan #{chosen}")
            st.rerun()

        # Supprimer
        if st.button("🗑️ Supprimer ce scan", type="secondary"):
            st.session_state.db.delete_scan(chosen)
            st.success(f"Scan #{chosen} supprimé.")
            st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# ONGLET 5 — À PROPOS
# ══════════════════════════════════════════════════════════════════════════════

with tab5:
    st.markdown("""
    <div class='detail-card'>
      <h2 style='color:#1D9E75; margin-top:0;'>⬡ NetScan Pro</h2>
      <p style='color:#4A5568;'>
        Outil pédagogique de supervision réseau développé dans le cadre du cours
        <strong>Administration et supervision des réseaux</strong>.
      </p>
      <hr style='border-color:#E2E8F0;'>

      <h4 style='color:#1A202C;'>🤖 IA utilisée</h4>
      <p style='color:#4A5568;'>
        <strong>Claude Sonnet (Anthropic)</strong> — utilisé pour la conception de l'architecture,
        la génération du code Python, le débogage des dépendances pysnmp,
        la migration vers l'API asynchrone, et la rédaction de la documentation.
      </p>
      <hr style='border-color:#E2E8F0;'>

      <h4 style='color:#1A202C;'>🛠️ Technologies</h4>
      <div style='display:flex; gap:10px; flex-wrap:wrap; margin-top:8px;'>
        <span style='background:#EBF8F5;color:#085041;padding:4px 14px;border-radius:999px;font-size:0.85rem;font-weight:600;'>Python 3.12</span>
        <span style='background:#EBF8F5;color:#085041;padding:4px 14px;border-radius:999px;font-size:0.85rem;font-weight:600;'>Streamlit</span>
        <span style='background:#EBF8F5;color:#085041;padding:4px 14px;border-radius:999px;font-size:0.85rem;font-weight:600;'>Plotly</span>
        <span style='background:#EBF8F5;color:#085041;padding:4px 14px;border-radius:999px;font-size:0.85rem;font-weight:600;'>pysnmp-lextudio</span>
        <span style='background:#EBF8F5;color:#085041;padding:4px 14px;border-radius:999px;font-size:0.85rem;font-weight:600;'>reportlab</span>
        <span style='background:#EBF8F5;color:#085041;padding:4px 14px;border-radius:999px;font-size:0.85rem;font-weight:600;'>SQLite</span>
        <span style='background:#EBF8F5;color:#085041;padding:4px 14px;border-radius:999px;font-size:0.85rem;font-weight:600;'>pandas</span>
      </div>
      <hr style='border-color:#E2E8F0;'>

      <h4 style='color:#1A202C;'>📡 OIDs SNMP interrogés</h4>
      <table style='width:100%; border-collapse:collapse; font-size:0.9rem;'>
        <tr style='background:#F8F9FA;'>
          <th style='padding:8px; text-align:left; color:#718096;'>OID</th>
          <th style='padding:8px; text-align:left; color:#718096;'>Nom</th>
          <th style='padding:8px; text-align:left; color:#718096;'>Information</th>
        </tr>
        <tr><td style='padding:8px; font-family:monospace;'>1.3.6.1.2.1.1.1.0</td><td style='padding:8px;'>sysDescr</td><td style='padding:8px;'>Description du système</td></tr>
        <tr style='background:#F8F9FA;'><td style='padding:8px; font-family:monospace;'>1.3.6.1.2.1.1.3.0</td><td style='padding:8px;'>sysUpTime</td><td style='padding:8px;'>Temps de fonctionnement</td></tr>
        <tr><td style='padding:8px; font-family:monospace;'>1.3.6.1.2.1.1.4.0</td><td style='padding:8px;'>sysContact</td><td style='padding:8px;'>Contact administrateur</td></tr>
        <tr style='background:#F8F9FA;'><td style='padding:8px; font-family:monospace;'>1.3.6.1.2.1.1.5.0</td><td style='padding:8px;'>sysName</td><td style='padding:8px;'>Nom de l'équipement</td></tr>
        <tr><td style='padding:8px; font-family:monospace;'>1.3.6.1.2.1.1.6.0</td><td style='padding:8px;'>sysLocation</td><td style='padding:8px;'>Localisation physique</td></tr>
        <tr style='background:#F8F9FA;'><td style='padding:8px; font-family:monospace;'>1.3.6.1.2.1.2.1.0</td><td style='padding:8px;'>ifNumber</td><td style='padding:8px;'>Nombre d'interfaces</td></tr>
      </table>
    </div>
    """, unsafe_allow_html=True)
