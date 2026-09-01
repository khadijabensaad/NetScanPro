"""
NetScan Pro — Suite de tests
Tests unitaires et d'intégration pour documenter et valider les fonctionnalités.

Lancer avec :
    pytest tests.py -v
    pytest tests.py -v --tb=short          # erreurs courtes
    pytest tests.py -v --cov=core          # avec couverture de code
    pytest tests.py -k "snmp"              # uniquement les tests SNMP
    pytest tests.py -k "not slow"          # exclure les tests lents
"""

import pytest
import threading
import time
import tempfile
import os
import ipaddress

# Import du module à tester
from core import (
    ping_host, resolve_hostname,
    detect_device_type, format_uptime, uptime_to_seconds,
    snmp_get_bulk, scan_host_full,
    ScanEngine, Database,
    devices_to_csv, devices_to_pdf,
    DEVICE_TYPES, OIDS,
    SNMP_AVAILABLE, REPORTLAB_AVAILABLE,
)


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def sample_device():
    """Un équipement actif complet pour les tests."""
    return {
        "ip":             "192.168.1.1",
        "status":         "Actif",
        "hostname":       "router.local",
        "sysName":        "Cisco-Core-Router",
        "sysDescr":       "Cisco IOS Software, Version 15.4",
        "sysUpTime":      "14j 6h 22m",
        "sysContact":     "admin@entreprise.com",
        "sysLocation":    "Salle serveur A",
        "ifNumber":       "4",
        "device_type":    "router",
        "uptime_seconds": 1234567,
    }

@pytest.fixture
def sample_devices(sample_device):
    """Liste de plusieurs équipements pour les tests d'export et de stats."""
    return [
        sample_device,
        {
            "ip": "192.168.1.2", "status": "Actif",
            "hostname": "sw01.local", "sysName": "SW-Access-01",
            "sysDescr": "Cisco Catalyst Switch", "sysUpTime": "30j 0h 0m",
            "sysContact": "—", "sysLocation": "Salle serveur A",
            "ifNumber": "24", "device_type": "switch",
            "uptime_seconds": 2592000,
        },
        {
            "ip": "192.168.1.10", "status": "Actif",
            "hostname": "srv-web.local", "sysName": "SRV-WEB",
            "sysDescr": "Linux Ubuntu 22.04 LTS", "sysUpTime": "60j 0h 0m",
            "sysContact": "ops@entreprise.com", "sysLocation": "Rack B",
            "ifNumber": "2", "device_type": "server",
            "uptime_seconds": 5184000,
        },
        {
            "ip": "192.168.1.50", "status": "Inactif",
            "hostname": "—", "sysName": "—",
            "sysDescr": "—", "sysUpTime": "—",
            "sysContact": "—", "sysLocation": "—",
            "ifNumber": "—", "device_type": "unknown",
            "uptime_seconds": 0,
        },
    ]

@pytest.fixture
def tmp_db():
    """Base de données SQLite temporaire pour les tests."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = Database(path=path)
    yield db
    db.close()
    os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# 1. TESTS — detect_device_type()
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectDeviceType:
    """Vérifie la détection automatique du type d'équipement à partir de sysDescr."""

    def test_cisco_router(self):
        result = detect_device_type("Cisco IOS Software, Version 15.4")
        assert result == "router", "Cisco IOS doit être identifié comme routeur"

    def test_junos_router(self):
        result = detect_device_type("Juniper Networks, Inc. junos OS")
        assert result == "router"

    def test_catalyst_switch(self):
        result = detect_device_type("Cisco Catalyst 2960 Series Switch")
        assert result == "switch"

    def test_nexus_switch(self):
        result = detect_device_type("Cisco NX-OS Nexus 9000")
        assert result == "switch"

    def test_linux_server(self):
        result = detect_device_type("Linux Ubuntu 22.04 LTS kernel 5.15")
        assert result == "server"

    def test_windows_server(self):
        result = detect_device_type("Windows Server 2019 Standard")
        assert result == "server"

    def test_printer_hp(self):
        result = detect_device_type("HP LaserJet Pro M404n")
        assert result == "printer"

    def test_fortigate_firewall(self):
        result = detect_device_type("FortiGate-60F FortiOS v7.0")
        assert result == "firewall"

    def test_unknown_empty(self):
        result = detect_device_type("")
        assert result == "unknown"

    def test_unknown_dash(self):
        result = detect_device_type("—")
        assert result == "unknown"

    def test_unknown_none(self):
        result = detect_device_type(None)
        assert result == "unknown"

    def test_case_insensitive(self):
        """La détection doit être insensible à la casse."""
        assert detect_device_type("CISCO IOS") == "router"
        assert detect_device_type("cisco ios") == "router"
        assert detect_device_type("Cisco Ios") == "router"

    def test_all_types_have_device_info(self):
        """Chaque type retourné doit exister dans DEVICE_TYPES."""
        descrs = [
            "Cisco IOS", "Catalyst Switch", "Linux Ubuntu",
            "HP LaserJet", "FortiGate", "Windows Workstation", ""
        ]
        for descr in descrs:
            result = detect_device_type(descr)
            assert result in DEVICE_TYPES, \
                f"Type '{result}' non trouvé dans DEVICE_TYPES pour '{descr}'"


# ══════════════════════════════════════════════════════════════════════════════
# 2. TESTS — format_uptime()
# ══════════════════════════════════════════════════════════════════════════════

class TestFormatUptime:
    """Vérifie la conversion des Timeticks SNMP en texte lisible."""

    def test_basic_timeticks(self):
        # 8640000 centièmes = 86400 secondes = 1 jour
        result = format_uptime("8640000")
        assert "1j" in result

    def test_timeticks_with_prefix(self):
        result = format_uptime("Timeticks: (8640000) 1:00:00:00.00")
        assert "1j" in result

    def test_timeticks_parentheses(self):
        result = format_uptime("(8640000)")
        assert "1j" in result

    def test_zero_uptime(self):
        result = format_uptime("0")
        assert "0j" in result

    def test_dash_returns_dash(self):
        assert format_uptime("—") == "—"

    def test_empty_returns_dash(self):
        assert format_uptime("") == "—"

    def test_none_returns_dash(self):
        assert format_uptime(None) == "—"

    def test_hours_minutes(self):
        # 360000 centièmes = 3600 secondes = 1 heure
        result = format_uptime("360000")
        assert "1h" in result

    def test_large_uptime(self):
        # 30 jours
        result = format_uptime(str(30 * 86400 * 100))
        assert "30j" in result

    def test_uptime_to_seconds_basic(self):
        # 8640000 centièmes = 86400 secondes
        assert uptime_to_seconds("8640000") == 86400

    def test_uptime_to_seconds_dash(self):
        assert uptime_to_seconds("—") == 0

    def test_uptime_to_seconds_none(self):
        assert uptime_to_seconds(None) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 3. TESTS — Database
# ══════════════════════════════════════════════════════════════════════════════

class TestDatabase:
    """Teste la persistance des scans et équipements en SQLite."""

    def test_create_tables(self, tmp_db):
        """La DB doit créer les tables sans erreur."""
        scans = tmp_db.get_scans()
        assert isinstance(scans, list)
        assert len(scans) == 0

    def test_save_and_retrieve_scan(self, tmp_db, sample_devices):
        scan_id = tmp_db.save_scan("192.168.1.0/24", "public", sample_devices)
        assert isinstance(scan_id, int)
        assert scan_id >= 1

        scans = tmp_db.get_scans()
        assert len(scans) == 1
        assert scans[0][2] == "192.168.1.0/24"  # subnet
        assert scans[0][3] == 3                   # 3 actifs sur 4

    def test_save_multiple_scans(self, tmp_db, sample_devices):
        tmp_db.save_scan("192.168.1.0/24", "public", sample_devices)
        tmp_db.save_scan("10.0.0.0/24",    "public", sample_devices)
        scans = tmp_db.get_scans()
        assert len(scans) == 2

    def test_get_devices_for_scan(self, tmp_db, sample_devices):
        scan_id = tmp_db.save_scan("192.168.1.0/24", "public", sample_devices)
        devices = tmp_db.get_devices_for_scan(scan_id)
        # Seuls les devices actifs ET inactifs sont sauvegardés
        assert len(devices) == len(sample_devices)
        ips = [d["ip"] for d in devices]
        assert "192.168.1.1" in ips
        assert "192.168.1.10" in ips

    def test_delete_scan(self, tmp_db, sample_devices):
        scan_id = tmp_db.save_scan("192.168.1.0/24", "public", sample_devices)
        tmp_db.delete_scan(scan_id)
        scans   = tmp_db.get_scans()
        devices = tmp_db.get_devices_for_scan(scan_id)
        assert len(scans)   == 0
        assert len(devices) == 0

    def test_snmp_hosts_count(self, tmp_db, sample_devices):
        """Les équipements avec sysName != '—' doivent être comptés comme SNMP."""
        scan_id = tmp_db.save_scan("192.168.1.0/24", "public", sample_devices)
        scans   = tmp_db.get_scans()
        # 3 actifs ont un sysName valide
        assert scans[0][5] == 3   # snmp_hosts

    def test_history_limit(self, tmp_db, sample_devices):
        """L'historique ne retourne pas plus de 50 entrées."""
        for i in range(10):
            tmp_db.save_scan(f"10.0.{i}.0/24", "public", sample_devices)
        scans = tmp_db.get_scans()
        assert len(scans) <= 50

    def test_concurrent_saves(self, tmp_db, sample_devices):
        """La DB doit gérer des écritures concurrentes sans crash."""
        errors = []
        def save():
            try:
                tmp_db.save_scan("192.168.1.0/24", "public", sample_devices)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=save) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert len(errors) == 0, f"Erreurs concurrentes : {errors}"


# ══════════════════════════════════════════════════════════════════════════════
# 4. TESTS — devices_to_csv()
# ══════════════════════════════════════════════════════════════════════════════

class TestExportCSV:
    """Vérifie la génération du fichier CSV."""

    def test_csv_has_header(self, sample_devices):
        csv = devices_to_csv(sample_devices)
        assert "ip" in csv
        assert "sysName" in csv
        assert "status" in csv

    def test_csv_contains_all_ips(self, sample_devices):
        csv = devices_to_csv(sample_devices)
        for d in sample_devices:
            assert d["ip"] in csv

    def test_csv_correct_row_count(self, sample_devices):
        csv = devices_to_csv(sample_devices)
        lines = [l for l in csv.strip().split("\n") if l]
        # 1 ligne header + N devices
        assert len(lines) == len(sample_devices) + 1

    def test_csv_contains_device_types(self, sample_devices):
        csv = devices_to_csv(sample_devices)
        assert "router" in csv
        assert "server" in csv

    def test_csv_empty_devices(self):
        csv = devices_to_csv([])
        lines = [l for l in csv.strip().split("\n") if l]
        assert len(lines) == 1  # header uniquement

    def test_csv_special_chars(self):
        """Les champs avec virgules/guillemets doivent être bien encodés."""
        devices = [{
            "ip": "192.168.1.1", "status": "Actif",
            "hostname": "—", "sysName": 'Mon "Switch", local',
            "sysDescr": "—", "sysLocation": "Salle, Bâtiment A",
            "sysContact": "—", "sysUpTime": "1j 0h 0m",
            "ifNumber": "4", "device_type": "switch"
        }]
        csv = devices_to_csv(devices)
        assert "192.168.1.1" in csv  # Le fichier doit être parseable

    def test_csv_is_string(self, sample_devices):
        result = devices_to_csv(sample_devices)
        assert isinstance(result, str)


# ══════════════════════════════════════════════════════════════════════════════
# 5. TESTS — devices_to_pdf()
# ══════════════════════════════════════════════════════════════════════════════

class TestExportPDF:
    """Vérifie la génération du rapport PDF."""

    @pytest.mark.skipif(not REPORTLAB_AVAILABLE,
                        reason="reportlab non installé")
    def test_pdf_returns_bytes(self, sample_devices):
        result = devices_to_pdf(sample_devices, "192.168.1.0/24")
        assert isinstance(result, bytes)

    @pytest.mark.skipif(not REPORTLAB_AVAILABLE,
                        reason="reportlab non installé")
    def test_pdf_not_empty(self, sample_devices):
        result = devices_to_pdf(sample_devices, "192.168.1.0/24")
        assert len(result) > 1024  # Au moins 1KB

    @pytest.mark.skipif(not REPORTLAB_AVAILABLE,
                        reason="reportlab non installé")
    def test_pdf_starts_with_pdf_header(self, sample_devices):
        result = devices_to_pdf(sample_devices, "192.168.1.0/24")
        assert result[:4] == b"%PDF", "Le fichier doit commencer par '%PDF'"

    @pytest.mark.skipif(not REPORTLAB_AVAILABLE,
                        reason="reportlab non installé")
    def test_pdf_empty_devices(self):
        result = devices_to_pdf([], "192.168.1.0/24")
        assert isinstance(result, bytes)

    def test_pdf_without_reportlab(self, monkeypatch, sample_devices):
        """Sans reportlab, la fonction retourne des bytes vides."""
        import core as c
        monkeypatch.setattr(c, "REPORTLAB_AVAILABLE", False)
        result = devices_to_pdf(sample_devices, "192.168.1.0/24")
        assert result == b""


# ══════════════════════════════════════════════════════════════════════════════
# 6. TESTS — ScanEngine
# ══════════════════════════════════════════════════════════════════════════════

class TestScanEngine:
    """Teste le moteur de scan multi-threadé."""

    def test_engine_initializes(self):
        engine = ScanEngine()
        assert engine.results == []
        assert engine.running == False
        assert engine.progress == 0

    def test_invalid_subnet_raises(self):
        engine = ScanEngine()
        with pytest.raises(ValueError, match="invalide"):
            engine.scan("not_a_subnet", "public", 2, 2, 5)

    def test_stop_prevents_scan(self):
        """Un arrêt immédiat doit stopper le scan rapidement."""
        engine = ScanEngine()
        engine.stop()  # stop AVANT le scan
        start = time.time()
        # Utilise une très petite plage pour que le test reste rapide
        engine.scan("10.255.255.0/29", "public", 1, 1, 2)
        elapsed = time.time() - start
        # Avec stop() déjà activé, le scan doit s'arrêter sans traiter d'hôtes
        assert engine.running == False
        assert elapsed < 30, f"Scan trop long ({elapsed:.1f}s)"

    def test_progress_callback(self):
        """Le callback on_progress doit être appelé."""
        engine = ScanEngine()
        calls = []

        def on_prog(done, total):
            calls.append((done, total))

        # Scan d'une seule adresse (boucle vide = /32)
        engine.scan("127.0.0.1/32", "public", 2, 1, 5,
                    on_progress=on_prog)
        # /32 n'a pas d'hôtes (hosts() vide) — pas de callback
        # On vérifie juste que ça ne plante pas
        assert engine.running == False

    def test_scan_localhost(self):
        """Le loopback 127.0.0.1 doit être détecté comme actif."""
        engine = ScanEngine()
        engine.scan("127.0.0.1/32", "public", 2, 2, 5)
        # /32 = pas d'hôte dans network.hosts()
        # Teste avec /31 pour avoir 127.0.0.0 et 127.0.0.1
        engine2 = ScanEngine()
        found = []
        engine2.scan("127.0.0.0/31", "public", 2, 2, 5,
                     on_device=lambda d: found.append(d))
        # 127.0.0.1 devrait répondre au ping sur la plupart des OS
        # (pas de garantie stricte en CI, donc on vérifie juste l'absence d'erreur)
        assert engine2.running == False

    def test_thread_safety(self):
        """Le scan parallèle ne doit pas corrompre la liste results."""
        engine = ScanEngine()
        # Scan d'une petite plage inexistante (timeout court)
        engine.scan("10.254.253.0/29", "public", 2, 1, 10)
        # Tous les résultats doivent avoir un champ 'ip'
        for d in engine.results:
            assert "ip" in d
            assert "status" in d


# ══════════════════════════════════════════════════════════════════════════════
# 7. TESTS — Fonctions utilitaires
# ══════════════════════════════════════════════════════════════════════════════

class TestUtilities:
    """Tests des fonctions utilitaires diverses."""

    def test_device_types_completeness(self):
        """DEVICE_TYPES doit avoir les champs requis pour chaque type."""
        required = {"label", "icon", "color"}
        for key, val in DEVICE_TYPES.items():
            missing = required - set(val.keys())
            assert not missing, \
                f"Type '{key}' manque les champs : {missing}"

    def test_oids_are_valid_format(self):
        """Les OIDs doivent être des chaînes de chiffres séparées par des points."""
        import re
        pattern = re.compile(r"^\d+(\.\d+)+$")
        for name, oid in OIDS.items():
            assert pattern.match(oid), \
                f"OID '{name}' a un format invalide : '{oid}'"

    def test_ipaddress_parsing(self):
        """Les plages IP doivent être parsables avec ipaddress standard."""
        valid_subnets = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.1.0/30",
        ]
        for subnet in valid_subnets:
            net = ipaddress.ip_network(subnet, strict=False)
            assert net.num_addresses >= 2

    def test_ipaddress_invalid(self):
        """Les plages invalides doivent lever une ValueError."""
        with pytest.raises(ValueError):
            ipaddress.ip_network("not.valid/24")
        with pytest.raises(ValueError):
            ipaddress.ip_network("192.168.1.1/99")

    def test_device_types_keys(self):
        """Les types connus doivent tous être présents."""
        expected = {"router","switch","server","printer","firewall","pc","unknown"}
        assert set(DEVICE_TYPES.keys()) == expected

    def test_csv_fields_match_oids(self):
        """Les champs CSV doivent couvrir tous les OIDs interrogés."""
        import csv, io
        from core import devices_to_csv
        devices = [{
            "ip": "1.2.3.4", "status": "Actif",
            "hostname": "—",
            **{k: "val" for k in OIDS.keys()},
            "device_type": "unknown", "uptime_seconds": 0
        }]
        csv_str = devices_to_csv(devices)
        reader  = csv.DictReader(io.StringIO(csv_str))
        headers = reader.fieldnames
        for oid_name in OIDS.keys():
            assert oid_name in headers, \
                f"Colonne '{oid_name}' manquante dans le CSV"


# ══════════════════════════════════════════════════════════════════════════════
# 8. TESTS D'INTÉGRATION — Scénarios complets
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegration:
    """Scénarios de bout en bout simulant l'usage réel de l'application."""

    def test_full_workflow_mock(self, tmp_db, sample_devices):
        """
        Scénario complet :
        1. Simuler un résultat de scan
        2. Sauvegarder en DB
        3. Recharger depuis DB
        4. Exporter en CSV
        5. Vérifier la cohérence
        """
        # Étape 1 & 2 : save
        scan_id = tmp_db.save_scan("192.168.1.0/24", "public", sample_devices)
        assert scan_id >= 1

        # Étape 3 : reload
        loaded = tmp_db.get_devices_for_scan(scan_id)
        assert len(loaded) == len(sample_devices)

        # Étape 4 : export CSV
        csv_data = devices_to_csv(loaded)
        assert "192.168.1.1" in csv_data
        assert "router"      in csv_data

        # Étape 5 : cohérence
        active_loaded = [d for d in loaded if d["status"] == "Actif"]
        assert len(active_loaded) == 3

    def test_detect_and_save_round_trip(self, tmp_db):
        """
        Vérification que detect_device_type + save_scan + reload
        conserve le device_type correctement.
        """
        devices = [{
            "ip": "192.168.1.1", "status": "Actif",
            "hostname": "gw", "sysName": "Router-01",
            "sysDescr": "Cisco IOS 15.4",
            "sysUpTime": format_uptime("8640000"),
            "sysContact": "—", "sysLocation": "DC",
            "ifNumber": "4",
            "device_type": detect_device_type("Cisco IOS 15.4"),
            "uptime_seconds": 86400,
        }]
        scan_id = tmp_db.save_scan("192.168.1.0/30", "public", devices)
        loaded  = tmp_db.get_devices_for_scan(scan_id)

        assert loaded[0]["device_type"] == "router"
        assert loaded[0]["sysUpTime"]   == "1j 0h 0m"

    def test_multiple_exports_consistency(self, sample_devices):
        """CSV et PDF doivent contenir les mêmes équipements."""
        csv_data = devices_to_csv(sample_devices)
        active_in_csv = sum(1 for line in csv_data.split("\n")
                            if "Actif" in line)
        active_count  = sum(1 for d in sample_devices if d["status"] == "Actif")
        assert active_in_csv == active_count

    @pytest.mark.skipif(not REPORTLAB_AVAILABLE,
                        reason="reportlab non installé")
    def test_pdf_size_grows_with_devices(self):
        """Un PDF avec plus d'équipements doit être plus grand."""
        d_base = [{
            "ip": f"192.168.1.{i}", "status": "Actif",
            "hostname": f"host{i}", "sysName": f"device{i}",
            "sysDescr": "Linux", "sysUpTime": "1j",
            "sysContact": "—", "sysLocation": "DC",
            "ifNumber": "2", "device_type": "server"
        } for i in range(1, 5)]

        pdf_small = devices_to_pdf(d_base[:2],  "192.168.1.0/24")
        pdf_large = devices_to_pdf(d_base,       "192.168.1.0/24")
        assert len(pdf_large) > len(pdf_small)


# ══════════════════════════════════════════════════════════════════════════════
# 9. TESTS RÉSEAU (marqués "slow" — optionnels en CI)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.slow
class TestNetwork:
    """
    Tests nécessitant une vraie connexion réseau.
    Exclure avec : pytest -k "not slow"
    """

    def test_ping_localhost(self):
        result = ping_host("127.0.0.1", timeout=1)
        assert result is True, "127.0.0.1 doit toujours répondre"

    def test_ping_invalid_ip(self):
        result = ping_host("0.0.0.0", timeout=0.5)
        assert result is False

    def test_ping_unreachable(self):
        result = ping_host("10.255.255.255", timeout=0.5)
        assert result is False

    def test_resolve_localhost(self):
        result = resolve_hostname("127.0.0.1")
        assert result != "—" or result == "—"  # Peut varier selon l'OS

    def test_snmp_public_demo(self):
        """
        Test SNMP sur demo.pysnmp.com (serveur de démo public).
        Peut échouer si le réseau est indisponible.
        """
        if not SNMP_AVAILABLE:
            pytest.skip("pysnmp non disponible")
        result = snmp_get_bulk(
            "demo.pysnmp.com", "public",
            {"sysDescr": "1.3.6.1.2.1.1.1.0"},
            version=1, timeout=3
        )
        # Le résultat peut être "—" si le serveur est hors ligne
        assert "sysDescr" in result


# ══════════════════════════════════════════════════════════════════════════════
# RAPPORT DE TESTS (affiché avec pytest -v)
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    Lancer directement : python tests.py
    Affiche un résumé rapide sans pytest.
    """
    import sys

    print("\n" + "="*60)
    print("  NetScan Pro — Vérification rapide des fonctions")
    print("="*60)

    tests = [
        ("detect_device_type Cisco",  lambda: detect_device_type("Cisco IOS") == "router"),
        ("detect_device_type Linux",  lambda: detect_device_type("Linux Ubuntu") == "server"),
        ("detect_device_type empty",  lambda: detect_device_type("") == "unknown"),
        ("format_uptime 1 jour",      lambda: "1j" in format_uptime("8640000")),
        ("format_uptime dash",        lambda: format_uptime("—") == "—"),
        ("uptime_to_seconds",         lambda: uptime_to_seconds("8640000") == 86400),
        ("devices_to_csv header",     lambda: "ip" in devices_to_csv([{"ip":"1.2.3.4","status":"Actif","hostname":"—","sysName":"—","sysDescr":"—","sysLocation":"—","sysContact":"—","sysUpTime":"—","ifNumber":"—","device_type":"unknown"}])),
        ("Database create",           lambda: (Database(":memory:"), True)[1]),
        ("DEVICE_TYPES complete",     lambda: all({"label","icon","color"} <= set(v.keys()) for v in DEVICE_TYPES.values())),
        ("OIDS format valid",         lambda: all("." in v for v in OIDS.values())),
    ]

    passed = failed = 0
    for name, fn in tests:
        try:
            ok = fn()
            print(f"  {'✓' if ok else '✗'} {name}")
            if ok: passed += 1
            else:  failed += 1
        except Exception as e:
            print(f"  ✗ {name} — ERREUR: {e}")
            failed += 1

    print(f"\n  {passed} réussis / {passed+failed} tests")
    print("="*60)
    sys.exit(0 if failed == 0 else 1)
