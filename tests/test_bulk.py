"""Tests for asset inventory resolution and the bulk scanner."""

from main.bulk_scanner import BulkScanner
from tools.asset_inventory import AssetInventory, OfflineCMDBBackend


def _inventory() -> AssetInventory:
    return AssetInventory(OfflineCMDBBackend())


def test_list_application_instances():
    apps = _inventory().list_application_instances()
    assert "Core Banking" in apps
    assert "CRM Production" in apps


def test_resolve_by_app_instance():
    inv = _inventory()
    servers = inv.resolve(app_instances=["Core Banking"])
    names = {s.name for s in servers}
    # Core Banking maps to mssql-fin-1, oracle-fin-1, pg-prod-1.
    assert {"mssql-fin-1", "oracle-fin-1", "pg-prod-1"} <= names
    assert all(s.app_instance == "Core Banking" for s in servers)


def test_resolve_by_hostname():
    inv = _inventory()
    servers = inv.resolve(hostnames=["app-web-01.corp"])
    assert {"mysql-prod-1", "pg-prod-1"} <= {s.name for s in servers}


def test_resolve_by_db_name_and_dedup():
    inv = _inventory()
    servers = inv.resolve(
        app_instances=["CRM Production"], db_servers=["pg-prod-1", "mysql-prod-1"]
    )
    names = [s.name for s in servers]
    # pg-prod-1 / mysql-prod-1 appear in CRM Production too: must be de-duplicated.
    assert len(names) == len(set(names))


def test_bulk_scan_app_instance_finds_issues():
    scanner = BulkScanner(inventory=_inventory())
    report = scanner.run(app_instances=["Core Banking"])
    assert report["resolved"] >= 3
    assert report["summary"]["total_targets"] >= 3
    assert report["summary"]["total_findings"] >= 1
    # mssql-fin-1 (sa/sa, default account) + oracle-fin-1 (public, changeme) are critical.
    assert report["summary"]["worst_severity"] == "critical"
    # Each target has all three agent results.
    for t in report["targets"]:
        assert set(t["results"].keys()) == {
            "Vulnerability Scanner Agent",
            "Threat Intelligence Agent",
            "Incident Response Agent",
        }


def test_bulk_scan_secure_server_has_fewer_findings():
    scanner = BulkScanner(inventory=_inventory())
    report = scanner.run(db_servers=["pg-prod-1"])
    assert report["summary"]["total_targets"] == 1
    # pg-prod-1 is TLS-on, private, strong password -> not critical.
    assert report["targets"][0]["severity"] != "critical"


def test_bulk_scan_empty_inputs():
    scanner = BulkScanner(inventory=_inventory())
    report = scanner.run()
    assert report["resolved"] == 0
    assert report["summary"]["total_targets"] == 0
