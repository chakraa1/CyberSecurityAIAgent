"""Asset inventory / CMDB resolution for bulk scanning.

Given heterogeneous inputs — bare hostnames, database-server names, or a
ServiceNow **Application Instance** — this module resolves the concrete set of
*database servers* that should be scanned.

Two backends:
* **ServiceNow (live)**: when ``SNOW_INSTANCE_URL`` / ``SNOW_USERNAME`` /
  ``SNOW_PASSWORD`` are configured, the CMDB is queried via the Table API
  (``cmdb_ci_appl`` + ``cmdb_rel_ci`` relationships) to discover the database
  CIs mapped to an application instance.
* **Offline fixture**: otherwise a bundled CMDB snapshot
  (``data/cmdb/cmdb.json``) is used so the whole bulk-scan flow is demonstrable
  without any external system.

The two backends expose the same :class:`AssetInventory` interface, so callers
(``main/bulk_scanner.py``) never need to know which one is active.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from typing import Dict, List, Optional

from config import get_logger, get_settings

logger = get_logger(__name__)


@dataclass
class DatabaseServer:
    """A scannable database server resolved from the inventory."""

    name: str
    engine: str
    hostname: str = ""
    host: str = ""
    port: int = 0
    ssl: bool = True
    username: str = ""
    password: str = ""
    public_access: bool = False
    default_account: bool = False
    app_instance: str = ""
    source: str = "offline-cmdb"

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_scan_config(self) -> Dict:
        """Shape expected by ``tools.vuln_scanner_tools.scan_database_config``."""
        return {
            "engine": self.engine,
            "host": self.host or self.hostname,
            "port": self.port,
            "ssl": self.ssl,
            "username": self.username,
            "password": self.password,
            "public_access": self.public_access,
            "default_account": self.default_account,
        }

    @property
    def key(self) -> str:
        return self.name or f"{self.engine}@{self.hostname or self.host}"


class AssetInventory:
    """Resolves inputs to :class:`DatabaseServer` objects via a CMDB backend."""

    def __init__(self, backend: "BaseCMDBBackend") -> None:
        self._backend = backend

    @property
    def source(self) -> str:
        return self._backend.source

    def list_application_instances(self) -> List[str]:
        return self._backend.list_application_instances()

    def resolve(
        self,
        hostnames: Optional[List[str]] = None,
        db_servers: Optional[List[str]] = None,
        app_instances: Optional[List[str]] = None,
    ) -> List[DatabaseServer]:
        """Resolve all inputs to a de-duplicated list of database servers."""
        resolved: Dict[str, DatabaseServer] = {}

        for app in app_instances or []:
            app = app.strip()
            if not app:
                continue
            for ds in self._backend.servers_for_app(app):
                resolved[ds.key] = ds

        for host in hostnames or []:
            host = host.strip()
            if not host:
                continue
            for ds in self._backend.servers_for_host(host):
                resolved.setdefault(ds.key, ds)

        for name in db_servers or []:
            name = name.strip()
            if not name:
                continue
            ds = self._backend.server_by_name(name)
            if ds:
                resolved.setdefault(ds.key, ds)
            else:
                logger.warning("Database server %r not found in inventory.", name)

        servers = list(resolved.values())
        logger.info("AssetInventory resolved %d database server(s) via %s.",
                    len(servers), self.source)
        return servers


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------
class BaseCMDBBackend:
    source = "base"

    def list_application_instances(self) -> List[str]:  # pragma: no cover
        raise NotImplementedError

    def servers_for_app(self, app_instance: str) -> List[DatabaseServer]:  # pragma: no cover
        raise NotImplementedError

    def servers_for_host(self, hostname: str) -> List[DatabaseServer]:  # pragma: no cover
        raise NotImplementedError

    def server_by_name(self, name: str) -> Optional[DatabaseServer]:  # pragma: no cover
        raise NotImplementedError


class OfflineCMDBBackend(BaseCMDBBackend):
    """CMDB backed by the bundled ``data/cmdb/cmdb.json`` fixture."""

    source = "offline-cmdb"

    def __init__(self) -> None:
        path = get_settings().data_dir / "cmdb" / "cmdb.json"
        with open(path, "r", encoding="utf-8") as fh:
            self._raw = json.load(fh)
        self._by_name = {s["name"]: s for s in self._raw.get("database_servers", [])}
        self._hosts = {h["hostname"]: h for h in self._raw.get("hosts", [])}
        self._apps = {a["name"]: a for a in self._raw.get("application_instances", [])}

    def _make(self, record: Dict, app_instance: str = "") -> DatabaseServer:
        return DatabaseServer(
            name=record.get("name", ""),
            engine=record.get("engine", ""),
            hostname=record.get("hostname", ""),
            host=record.get("host", ""),
            port=int(record.get("port", 0) or 0),
            ssl=bool(record.get("ssl", True)),
            username=record.get("username", ""),
            password=record.get("password", ""),
            public_access=bool(record.get("public_access", False)),
            default_account=bool(record.get("default_account", False)),
            app_instance=app_instance,
            source=self.source,
        )

    def list_application_instances(self) -> List[str]:
        return sorted(self._apps.keys())

    def servers_for_app(self, app_instance: str) -> List[DatabaseServer]:
        app = self._apps.get(app_instance)
        if not app:
            # Case-insensitive fallback match.
            for name, rec in self._apps.items():
                if name.lower() == app_instance.lower():
                    app = rec
                    break
        if not app:
            logger.warning("Application instance %r not found in CMDB.", app_instance)
            return []
        out = []
        for ds_name in app.get("database_servers", []):
            rec = self._by_name.get(ds_name)
            if rec:
                out.append(self._make(rec, app_instance=app["name"]))
        return out

    def servers_for_host(self, hostname: str) -> List[DatabaseServer]:
        out: List[DatabaseServer] = []
        host = self._hosts.get(hostname)
        if host:
            for ds_name in host.get("database_servers", []):
                rec = self._by_name.get(ds_name)
                if rec:
                    out.append(self._make(rec))
        # Also treat a hostname that *is* a database server's hostname.
        for rec in self._raw.get("database_servers", []):
            if rec.get("hostname") == hostname:
                out.append(self._make(rec))
        return out

    def server_by_name(self, name: str) -> Optional[DatabaseServer]:
        rec = self._by_name.get(name)
        if not rec:
            for n, r in self._by_name.items():
                if n.lower() == name.lower():
                    rec = r
                    break
        return self._make(rec) if rec else None


class ServiceNowCMDBBackend(BaseCMDBBackend):
    """CMDB backed by a live ServiceNow instance (Table API).

    Falls back to the offline backend on any error so bulk scanning never hard
    fails because of connectivity/permission issues.
    """

    source = "servicenow"

    # CMDB classes that represent database servers / instances.
    _DB_CLASSES = (
        "cmdb_ci_database",
        "cmdb_ci_db_mssql_instance",
        "cmdb_ci_db_mysql_instance",
        "cmdb_ci_db_ora_instance",
        "cmdb_ci_db_postgresql_instance",
    )

    def __init__(self) -> None:
        s = get_settings()
        self._base = s.snow_instance_url.rstrip("/")
        self._auth = (s.snow_username, s.snow_password)
        self._fallback = OfflineCMDBBackend()

    def _get(self, table: str, query: str, fields: str = "") -> List[Dict]:
        import requests

        url = f"{self._base}/api/now/table/{table}"
        params = {"sysparm_query": query, "sysparm_limit": "200"}
        if fields:
            params["sysparm_fields"] = fields
        resp = requests.get(
            url, params=params, auth=self._auth,
            headers={"Accept": "application/json"}, timeout=20,
        )
        resp.raise_for_status()
        return resp.json().get("result", [])

    @staticmethod
    def _engine_from_class(sys_class: str) -> str:
        mapping = {
            "cmdb_ci_db_mssql_instance": "mssql",
            "cmdb_ci_db_mysql_instance": "mysql",
            "cmdb_ci_db_ora_instance": "oracle",
            "cmdb_ci_db_postgresql_instance": "postgres",
        }
        return mapping.get(sys_class, "database")

    def list_application_instances(self) -> List[str]:
        try:
            rows = self._get("cmdb_ci_appl", "ORDERBYname", "name")
            names = sorted({r["name"] for r in rows if r.get("name")})
            return names or self._fallback.list_application_instances()
        except Exception as exc:  # pragma: no cover - network
            logger.warning("ServiceNow list apps failed (%s); using fixture.", exc)
            return self._fallback.list_application_instances()

    def _ci_to_server(self, ci: Dict, app_instance: str = "") -> DatabaseServer:
        return DatabaseServer(
            name=ci.get("name", ci.get("sys_id", "")),
            engine=self._engine_from_class(ci.get("sys_class_name", "")),
            hostname=ci.get("dns_domain") or ci.get("fqdn") or ci.get("name", ""),
            host=ci.get("ip_address", ""),
            port=int(ci.get("tcp_port", 0) or 0),
            ssl=str(ci.get("ssl_enabled", "")).lower() in ("true", "1", "yes"),
            username=ci.get("user", ""),
            password="",  # never pulled from CMDB
            public_access=str(ci.get("public", "")).lower() in ("true", "1", "yes"),
            default_account=False,
            app_instance=app_instance,
            source=self.source,
        )

    def servers_for_app(self, app_instance: str) -> List[DatabaseServer]:
        try:
            apps = self._get("cmdb_ci_appl", f"name={app_instance}", "sys_id,name")
            if not apps:
                return self._fallback.servers_for_app(app_instance)
            app_sys_id = apps[0]["sys_id"]
            rels = self._get(
                "cmdb_rel_ci",
                f"parent={app_sys_id}^ORchild={app_sys_id}",
                "parent,child",
            )
            ci_ids = set()
            for rel in rels:
                for side in ("parent", "child"):
                    val = rel.get(side)
                    sys_id = val.get("value") if isinstance(val, dict) else val
                    if sys_id and sys_id != app_sys_id:
                        ci_ids.add(sys_id)
            servers: List[DatabaseServer] = []
            for sys_id in ci_ids:
                for cls in self._DB_CLASSES:
                    cis = self._get(cls, f"sys_id={sys_id}")
                    for ci in cis:
                        servers.append(self._ci_to_server(ci, app_instance))
            return servers or self._fallback.servers_for_app(app_instance)
        except Exception as exc:  # pragma: no cover - network
            logger.warning("ServiceNow servers_for_app failed (%s); fixture.", exc)
            return self._fallback.servers_for_app(app_instance)

    def servers_for_host(self, hostname: str) -> List[DatabaseServer]:
        try:
            servers: List[DatabaseServer] = []
            for cls in self._DB_CLASSES:
                for ci in self._get(cls, f"nameLIKE{hostname}^ORfqdnLIKE{hostname}"):
                    servers.append(self._ci_to_server(ci))
            return servers or self._fallback.servers_for_host(hostname)
        except Exception as exc:  # pragma: no cover - network
            logger.warning("ServiceNow servers_for_host failed (%s); fixture.", exc)
            return self._fallback.servers_for_host(hostname)

    def server_by_name(self, name: str) -> Optional[DatabaseServer]:
        try:
            for cls in self._DB_CLASSES:
                cis = self._get(cls, f"name={name}")
                if cis:
                    return self._ci_to_server(cis[0])
            return self._fallback.server_by_name(name)
        except Exception as exc:  # pragma: no cover - network
            logger.warning("ServiceNow server_by_name failed (%s); fixture.", exc)
            return self._fallback.server_by_name(name)


@lru_cache(maxsize=1)
def get_inventory() -> AssetInventory:
    """Return the active inventory (ServiceNow if configured, else offline)."""
    settings = get_settings()
    if settings.has_servicenow:
        logger.info("AssetInventory: using live ServiceNow CMDB at %s.",
                    settings.snow_instance_url)
        return AssetInventory(ServiceNowCMDBBackend())
    logger.info("AssetInventory: using offline CMDB fixture.")
    return AssetInventory(OfflineCMDBBackend())
