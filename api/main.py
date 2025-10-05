import os, json, uuid, datetime
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, text

API_TOKEN = os.getenv("API_TOKEN", "change-me")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://app:app@db:5432/vuln")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

app = FastAPI(title="Vuln Ingest API", version="1.0.0")

# --- auth ---
def require_token(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.split(" ", 1)[1]
    if token != API_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")
    return True

# --- helpers ---
def db_execute(sql: str, **params):
    with engine.begin() as conn:
        return conn.execute(text(sql), params)

def create_run(repo, commit, branch, image, ci_run_id=None):
    rid = str(uuid.uuid4())
    db_execute("""
      INSERT INTO runs (id, ci_run_id, repo, commit_sha, branch, image)
      VALUES (:id, :ci, :repo, :commit, :branch, :image)
    """, id=rid, ci=ci_run_id, repo=repo, commit=commit, branch=branch, image=image)
    return rid

def upsert_component(purl: Optional[str], name: Optional[str], version: Optional[str]) -> Optional[int]:
    if not (purl or name or version):
        return None
    r = db_execute("""
      INSERT INTO components (purl, name, version)
      VALUES (:purl, :name, :version)
      ON CONFLICT (purl, name, version) DO UPDATE SET purl=EXCLUDED.purl
      RETURNING id
    """, purl=purl, name=name, version=version).first()
    return int(r[0]) if r else None

def insert_finding(run_id, source, vuln_id, severity, cvss_score, description, fix_version, component_id, layer, raw):
    db_execute("""
      INSERT INTO findings (run_id, source, vuln_id, severity, cvss_score, description, fix_version, component_id, layer, raw)
      VALUES (:run_id, :source, :vuln_id, :severity, :cvss, :desc, :fix, :cid, :layer, :raw)
    """, run_id=run_id, source=source, vuln_id=vuln_id, severity=severity,
       cvss=cvss_score, desc=description, fix=fix_version, cid=component_id, layer=layer, raw=json.dumps(raw))

# --- extractors ---
def extract_cvss_from_trivy(v: dict) -> Optional[float]:
    # Trivy podaje CVSS w polach "CVSS": {"nvd": {"V3Score": ...}, ...}
    cvss = v.get("CVSS") or {}
    for k in ("nvd", "ghsa", "redhat"):
        sc = cvss.get(k) or {}
        for key in ("V3Score", "V2Score", "Score"):
            if sc.get(key) is not None:
                return float(sc[key])
    return None

def extract_cvss_from_grype(v: dict) -> Optional[float]:
    # Grype: vulnerability.cvss = [{ baseScore, vector, source }]
    scores = v.get("cvss") or []
    if scores:
        try:
            return float(scores[0].get("baseScore"))
        except Exception:
            return None
    return None

def normalize_severity(s: Optional[str]) -> Optional[str]:
    if not s: return None
    s = s.strip().capitalize()
    mapping = {
        "critical":"Critical","high":"High","medium":"Medium","low":"Low",
        "negligible":"Negligible","unknown":"Unknown"
    }
    return mapping.get(s.lower(), s)

# --- ingest endpoints ---
@app.post("/ingest/trivy")
async def ingest_trivy(
    trivy_file: UploadFile = File(...),
    image: str = Form(...),
    repo: str = Form(...),
    commit: str = Form(...),
    branch: str = Form(...),
    ci_run_id: Optional[str] = Form(None),
    _auth=Depends(require_token),
):
    data = json.loads((await trivy_file.read()).decode("utf-8") or "{}")
    run_id = create_run(repo, commit, branch, image, ci_run_id)
    for res in data.get("Results", []) or []:
        vulns = res.get("Vulnerabilities") or []
        for v in vulns:
            comp = upsert_component(v.get("PURL"), v.get("PkgName"), v.get("InstalledVersion"))
            insert_finding(
                run_id=run_id,
                source="trivy",
                vuln_id=v.get("VulnerabilityID"),
                severity=normalize_severity(v.get("Severity")),
                cvss_score=extract_cvss_from_trivy(v),
                description=v.get("Title") or v.get("Description"),
                fix_version=v.get("FixedVersion"),
                component_id=comp,
                layer=(v.get("Layer") or {}).get("Digest"),
                raw=v,
            )
    return {"ok": True, "run_id": run_id}

@app.post("/ingest/grype")
async def ingest_grype(
    grype_file: UploadFile = File(...),
    image: str = Form(...),
    repo: str = Form(...),
    commit: str = Form(...),
    branch: str = Form(...),
    ci_run_id: Optional[str] = Form(None),
    _auth=Depends(require_token),
):
    data = json.loads((await grype_file.read()).decode("utf-8") or "{}")
    run_id = create_run(repo, commit, branch, image, ci_run_id)
    matches = data.get("matches") or []
    for m in matches:
        v = (m.get("vulnerability") or {})
        a = (m.get("artifact") or {})
        comp = upsert_component(a.get("purl"), a.get("name"), a.get("version"))
        insert_finding(
            run_id=run_id,
            source="grype",
            vuln_id=v.get("id"),
            severity=normalize_severity(v.get("severity")),
            cvss_score=extract_cvss_from_grype(v),
            description=v.get("dataSource") or v.get("description"),
            fix_version=(v.get("fix") or {}).get("version"),
            component_id=comp,
            layer=None,
            raw=m,
        )
    return {"ok": True, "run_id": run_id}

@app.post("/ingest/clair-sarif")
async def ingest_clair_sarif(
    sarif: UploadFile = File(...),
    image: str = Form(...),
    repo: str = Form(...),
    commit: str = Form(...),
    branch: str = Form(...),
    ci_run_id: Optional[str] = Form(None),
    _auth=Depends(require_token),
):
    # SARIF parsing – minimal
    content = (await sarif.read()).decode("utf-8", "ignore")
    data = json.loads(content or "{}")
    run_id = create_run(repo, commit, branch, image, ci_run_id)

    for run in data.get("runs", []) or []:
        results = run.get("results") or []
        rules_by_id = {}
        try:
            for r in (run.get("tool") or {}).get("driver", {}).get("rules", []) or []:
                rules_by_id[r.get("id")] = r
        except Exception:
            pass

        for r in results:
            rule_id = r.get("ruleId")
            rule = rules_by_id.get(rule_id, {})
            props = (rule.get("properties") or {}) | (r.get("properties") or {})
            severity = props.get("problem.severity") or props.get("security-severity") or r.get("level")
            cve = (props.get("tags") or [None])[0] if props.get("tags") else (rule.get("id") or rule_id)
            desc = (rule.get("shortDescription") or {}).get("text") or (rule.get("fullDescription") or {}).get("text")

            comp = upsert_component(
                purl=props.get("purl"),
                name=props.get("package"),
                version=props.get("version"),
            )
            insert_finding(
                run_id=run_id,
                source="clair",
                vuln_id=cve,
                severity=normalize_severity(severity),
                cvss_score=None,
                description=desc,
                fix_version=props.get("fixedVersion"),
                component_id=comp,
                layer=None,
                raw=r,
            )
    return {"ok": True, "run_id": run_id}

# --- simple read APIs for UI/Metabase prototyping ---
@app.get("/runs")
def list_runs(limit: int = 50, offset: int = 0, _auth=Depends(require_token)):
    rs = db_execute("""
      SELECT id, repo, commit_sha, branch, image, created_at
      FROM runs ORDER BY created_at DESC
      LIMIT :l OFFSET :o
    """, l=limit, o=offset).mappings().all()
    return rs

@app.get("/runs/{run_id}/findings")
def run_findings(run_id: str, _auth=Depends(require_token)):
    fs = db_execute("""
      SELECT f.id, f.source, f.vuln_id, f.severity, f.cvss_score, f.fix_version,
             c.name, c.version, c.purl, f.created_at
      FROM findings f
      LEFT JOIN components c ON c.id = f.component_id
      WHERE f.run_id = :rid
      ORDER BY
        CASE WHEN f.severity='Critical' THEN 1
             WHEN f.severity='High' THEN 2
             WHEN f.severity='Medium' THEN 3
             WHEN f.severity='Low' THEN 4
             ELSE 5 END, f.id DESC
    """, rid=run_id).mappings().all()
    return fs
