import os, json, sqlite3, datetime
from typing import Optional

DB_PATH = os.getenv("DB_PATH", "./data/vuln.sqlite")

def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with _conn() as c:
        c.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            repo TEXT, branch TEXT, commit TEXT,
            image TEXT
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS components (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            purl TEXT, name TEXT, version TEXT,
            UNIQUE(purl, name, version)
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            source TEXT,
            vuln_id TEXT,
            severity TEXT,
            cvss_score REAL,
            description TEXT,
            fix_version TEXT,
            component_id INTEGER,
            layer TEXT,
            raw_json TEXT,
            FOREIGN KEY(run_id) REFERENCES runs(id),
            FOREIGN KEY(component_id) REFERENCES components(id)
        )""")

def _now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def create_run(repo: str, commit: str, branch: str, image: str) -> str:
    run_id = os.urandom(16).hex()
    with _conn() as c:
        c.execute("INSERT INTO runs (id, created_at, repo, branch, commit, image) VALUES (?,?,?,?,?,?)",
                  (run_id, _now_iso(), repo, branch, commit, image))
    return run_id

def upsert_component(purl: Optional[str], name: Optional[str], version: Optional[str]) -> int:
    with _conn() as c:
        cur = c.execute("SELECT id FROM components WHERE IFNULL(purl,'')=IFNULL(?, '') AND IFNULL(name,'')=IFNULL(?, '') AND IFNULL(version,'')=IFNULL(?, '')",
                        (purl, name, version))
        row = cur.fetchone()
        if row: return row["id"]
        c.execute("INSERT INTO components (purl, name, version) VALUES (?,?,?)", (purl, name, version))
        return c.lastrowid

def insert_finding(run_id, source, vuln_id, severity, cvss_score, description, fix_version, component_id, layer, raw):
    with _conn() as c:
        c.execute("""
        INSERT INTO findings (run_id, source, vuln_id, severity, cvss_score, description, fix_version, component_id, layer, raw_json)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (run_id, source, vuln_id, severity, cvss_score, description, fix_version, component_id, layer, json.dumps(raw)))

def list_runs(limit=50, offset=0):
    with _conn() as c:
        cur = c.execute("""
        SELECT * FROM runs ORDER BY datetime(created_at) DESC LIMIT ? OFFSET ?""", (limit, offset))
        return cur.fetchall()

def list_findings(run_id):
    with _conn() as c:
        cur = c.execute("""
        SELECT f.*, coalesce(c.name, c.purl) as component_name, c.version as component_version
        FROM findings f LEFT JOIN components c ON f.component_id = c.id
        WHERE run_id = ?
        ORDER BY
          CASE lower(coalesce(severity, 'unknown'))
            WHEN 'critical' THEN 0
            WHEN 'high' THEN 1
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 3
            WHEN 'negligible' THEN 4
            ELSE 5
          END, coalesce(cvss_score, -1) DESC
        """, (run_id,))
        return cur.fetchall()

def dashboard_counts():
    with _conn() as c:
        rtotal = c.execute("SELECT count(*) AS cnt FROM runs").fetchone()["cnt"]
        latest = c.execute("SELECT created_at FROM runs ORDER BY datetime(created_at) DESC LIMIT 1").fetchone()
        latest = latest["created_at"] if latest else None
        by_sev = {}
        for sev in ("Critical","High","Medium","Low","Negligible","Unknown"):
            row = c.execute("SELECT count(*) AS cnt FROM findings WHERE severity=?", (sev,)).fetchone()
            by_sev[sev] = row["cnt"]
        return {"runs": rtotal, "latest": latest, "by_severity": by_sev}
