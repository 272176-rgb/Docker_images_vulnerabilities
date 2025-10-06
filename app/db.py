import os, sqlite3, uuid, datetime, json
from contextlib import contextmanager

DB_PATH = os.getenv("DB_PATH", "/data/vuln.sqlite")

@contextmanager
def conn():
    cx = sqlite3.connect(DB_PATH)
    cx.row_factory = sqlite3.Row
    try:
        yield cx
        cx.commit()
    finally:
        cx.close()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with conn() as cx:
        with open(os.path.join(os.path.dirname(__file__), "schema.sql"), "r", encoding="utf-8") as f:
            cx.executescript(f.read())

def iso_now():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def create_run(repo, commit, branch, image):
    rid = str(uuid.uuid4())
    with conn() as cx:
        cx.execute("""
          INSERT INTO runs (id, repo, commit_sha, branch, image, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        """, (rid, repo, commit, branch, image, iso_now()))
    return rid

def upsert_component(purl, name, version):
    if not (purl or name or version):
        return None
    with conn() as cx:
        cur = cx.execute("""
          INSERT OR IGNORE INTO components (purl, name, version) VALUES (?, ?, ?)
        """, (purl, name, version))
        # fetch id (existing or new)
        row = cx.execute("""
          SELECT id FROM components WHERE IFNULL(purl,'')=IFNULL(?,'') AND IFNULL(name,'')=IFNULL(?,'') AND IFNULL(version,'')=IFNULL(?,'')
        """, (purl, name, version)).fetchone()
        return row["id"] if row else None

def insert_finding(run_id, source, vuln_id, severity, cvss_score, description, fix_version, component_id, layer, raw):
    with conn() as cx:
        cx.execute("""
          INSERT INTO findings (run_id, source, vuln_id, severity, cvss_score, description, fix_version, component_id, layer, raw_json, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (run_id, source, vuln_id, severity, cvss_score, description, fix_version, component_id, layer, json.dumps(raw) if raw else None, iso_now()))

def list_runs(limit=50, offset=0):
    with conn() as cx:
        return cx.execute("""
          SELECT id, repo, commit_sha, branch, image, created_at
          FROM runs ORDER BY created_at DESC LIMIT ? OFFSET ?
        """, (limit, offset)).fetchall()

def list_findings(run_id):
    with conn() as cx:
        return cx.execute("""
          SELECT f.*, c.name as comp_name, c.version as comp_version, c.purl as comp_purl
          FROM findings f LEFT JOIN components c ON c.id=f.component_id
          WHERE f.run_id=? 
          ORDER BY 
            CASE lower(IFNULL(severity,'')) 
              WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 
              WHEN 'low' THEN 4 ELSE 5 END,
            f.id DESC
        """, (run_id,)).fetchall()

def dashboard_counts():
    with conn() as cx:
        by_sev = cx.execute("""
          SELECT COALESCE(severity,'unknown') as sev, COUNT(*) as cnt
          FROM findings GROUP BY COALESCE(severity,'unknown')
        """).fetchall()
        runs_total = cx.execute("SELECT COUNT(*) as c FROM runs").fetchone()["c"]
        latest = cx.execute("SELECT created_at FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
        return {
            "by_severity": {r["sev"]: r["cnt"] for r in by_sev},
            "runs": runs_total,
            "latest": latest["created_at"] if latest else None
        }
