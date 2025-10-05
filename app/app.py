import os, json
from flask import Flask, request, render_template, redirect, url_for, abort
from flask_cors import CORS
from app.db import init_db, create_run, upsert_component, insert_finding, list_runs, list_findings, dashboard_counts

APP_TOKEN = os.getenv("APP_TOKEN", "changeme-token")

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

@app.before_first_request
def _init():
    init_db()

def require_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): abort(401)
    if auth.split(" ",1)[1] != APP_TOKEN: abort(403)

def norm_sev(s):
    if not s: return None
    m = {"critical":"Critical","high":"High","medium":"Medium","low":"Low","negligible":"Negligible","unknown":"Unknown"}
    return m.get(s.lower(), s)

def cvss_from_trivy(v):
    cvss = v.get("CVSS") or {}
    for k in ("nvd","ghsa","redhat"):
        sc = cvss.get(k) or {}
        for key in ("V3Score","V2Score","Score"):
            if sc.get(key) is not None:
                try: return float(sc[key])
                except: pass
    return None

def cvss_from_grype(v):
    scores = v.get("cvss") or []
    if scores:
        try: return float(scores[0].get("baseScore"))
        except: return None
    return None

# ---------- HTML ----------
@app.get("/")
def index():
    counts = dashboard_counts()
    runs = list_runs(limit=20, offset=0)
    return render_template("index.html", counts=counts, runs=runs)

@app.get("/runs/<run_id>")
def run_page(run_id):
    items = list_findings(run_id)
    return render_template("run.html", run_id=run_id, findings=items)

# ---------- API: ingest ----------
@app.post("/ingest/trivy")
def ingest_trivy():
    require_token()
    data = request.get_json(force=True, silent=False)
    image = request.args.get("image") or data.get("Image") or "unknown"
    repo = request.args.get("repo") or "unknown"
    commit = request.args.get("commit") or "unknown"
    branch = request.args.get("branch") or "unknown"

    run_id = create_run(repo, commit, branch, image)

    for res in (data.get("Results") or []):
        vulns = res.get("Vulnerabilities") or []
        for v in vulns:
            comp = upsert_component(v.get("PURL"), v.get("PkgName"), v.get("InstalledVersion"))
            insert_finding(
                run_id=run_id,
                source="trivy",
                vuln_id=v.get("VulnerabilityID"),
                severity=norm_sev(v.get("Severity")),
                cvss_score=cvss_from_trivy(v),
                description=v.get("Title") or v.get("Description"),
                fix_version=v.get("FixedVersion"),
                component_id=comp,
                layer=(v.get("Layer") or {}).get("Digest"),
                raw=v
            )
    return {"ok": True, "run_id": run_id}

@app.post("/ingest/grype")
def ingest_grype():
    require_token()
    data = request.get_json(force=True, silent=False)
    image = request.args.get("image") or "unknown"
    repo = request.args.get("repo") or "unknown"
    commit = request.get_json(silent=True) or {}
    commit = request.args.get("commit") or "unknown"
    branch = request.args.get("branch") or "unknown"

    run_id = create_run(repo, commit, branch, image)

    for m in (data.get("matches") or []):
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        comp = upsert_component(a.get("purl"), a.get("name"), a.get("version"))
        insert_finding(
            run_id=run_id,
            source="grype",
            vuln_id=v.get("id"),
            severity=norm_sev(v.get("severity")),
            cvss_score=cvss_from_grype(v),
            description=v.get("dataSource") or v.get("description"),
            fix_version=(v.get("fix") or {}).get("version"),
            component_id=comp,
            layer=None,
            raw=m
        )
    return {"ok": True, "run_id": run_id}

# ---------- API: read ----------
@app.get("/api/runs")
def api_runs():
    return {"runs": [dict(r) for r in list_runs()]}

@app.get("/api/runs/<run_id>/findings")
def api_run_findings(run_id):
    return {"findings": [dict(r) for r in list_findings(run_id)]}

if __name__ == "__main__":
    # dev only; w Dockerze użyjemy waitress
    app.run(host="0.0.0.0", port=8000, debug=True)
