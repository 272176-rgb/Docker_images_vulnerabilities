import os, json
from flask import Flask, request, render_template, jsonify, abort
from flask_cors import CORS
from app.db import (
    init_db, create_run, upsert_component, insert_finding,
    list_runs, list_findings, dashboard_counts
)

APP_TOKEN = os.getenv("APP_TOKEN", "changeme-token")

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

@app.before_first_request
def _init():
    init_db()

def require_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        abort(401)
    if auth.split(" ", 1)[1] != APP_TOKEN:
        abort(403)

def norm_sev(s):
    if not s:
        return None
    m = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "negligible": "Negligible",
        "unknown": "Unknown",
    }
    return m.get(s.lower(), s)

def cvss_from_trivy(v):
    cvss = v.get("CVSS") or {}
    for k in ("nvd", "ghsa", "redhat"):
        sc = cvss.get(k) or {}
        for key in ("V3Score", "V2Score", "Score"):
            if sc.get(key) is not None:
                try:
                    return float(sc[key])
                except Exception:
                    pass
    return None

def cvss_from_grype(v):
    scores = v.get("cvss") or []
    if scores:
        try:
            return float(scores[0].get("baseScore"))
        except Exception:
            return None
    return None

# ---------- HTML ----------
@app.get("/")
def index():
    counts = dashboard_counts() or {}
    runs = list_runs(limit=20, offset=0) or []
    return render_template("index.html", counts=counts, runs=runs)

@app.get("/runs/<run_id>")
def run_page(run_id):
    items = list_findings(run_id) or []
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
                raw=v,
            )
    return {"ok": True, "run_id": run_id}

@app.post("/ingest/grype")
def ingest_grype():
    require_token()
    data = request.get_json(force=True, silent=False)
    image = request.args.get("image") or "unknown"
    repo = request.args.get("repo") or "unknown"
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
            raw=m,
        )
    return {"ok": True, "run_id": run_id}

@app.post("/ingest/clair-sarif")
def ingest_clair_sarif():
    """
    Przyjmuje plik SARIF wygenerowany przez Clair v4 (multipart: field 'sarif').
    Alternatywnie zaakceptuje application/json z samym SARIF-em.
    """
    require_token()

    # Meta z query
    image = request.args.get("image") or "unknown"
    repo = request.args.get("repo") or "unknown"
    commit = request.args.get("commit") or "unknown"
    branch = request.args.get("branch") or "unknown"

    # Wczytanie SARIF: multipart albo application/json
    sarif_data = None
    if request.files.get("sarif"):
        sarif_data = json.load(request.files["sarif"])
    else:
        sarif_data = request.get_json(force=True, silent=False)

    if not sarif_data:
        abort(400, description="No SARIF provided")

    run_id = create_run(repo, commit, branch, image)

    # Mapowanie severity z SARIF "level"
    def sev_from_level(level: str | None) -> str | None:
        if not level:
            return None
        m = {
            "error": "High",
            "warning": "Medium",
            "note": "Low",
            "none": "Unknown",
            "off": "Unknown",
        }
        return m.get(level.lower(), "Unknown")

    runs = sarif_data.get("runs") or []
    for r in runs:
        tool = (r.get("tool") or {})
        rules = { (rule.get("id") or ""): rule for rule in (tool.get("driver", {}) or {}).get("rules", []) or [] }

        for res in (r.get("results") or []):
            rule_id = res.get("ruleId")
            rule = rules.get(rule_id, {}) if rule_id else {}
            props = res.get("properties") or {}

            # Clair zwykle podaje ID CVE w ruleId albo w properties
            vuln_id = (
                props.get("cve") or
                rule.get("properties", {}).get("tags", [None])[0] or
                rule_id or "UNKNOWN"
            )

            # Próba wyciągnięcia komponentu / wersji z properties (zależnie od wersji SARIF z Clair)
            comp_purl = props.get("purl") or None
            comp_name = props.get("package") or props.get("pkg") or None
            comp_ver  = props.get("installedVersion") or props.get("version") or None
            component_id = upsert_component(comp_purl, comp_name, comp_ver)

            # Opis i CVSS (jeśli Clair coś poda w properties)
            description = None
            if res.get("message", {}).get("text"):
                description = res["message"]["text"]
            elif rule.get("fullDescription", {}).get("text"):
                description = rule["fullDescription"]["text"]
            elif rule.get("shortDescription", {}).get("text"):
                description = rule["shortDescription"]["text"]

            cvss = None
            for k in ("cvssScore", "cvss_v3", "cvss_v2"):
                v = props.get(k)
                try:
                    if v is not None:
                        cvss = float(v)
                        break
                except:
                    pass

            severity = sev_from_level(res.get("level"))
            insert_finding(
                run_id=run_id,
                source="clair",
                vuln_id=vuln_id,
                severity=norm_sev(severity),
                cvss_score=cvss,
                description=description,
                fix_version=props.get("fixedVersion") or None,
                component_id=component_id,
                layer=None,
                raw=res
            )

    return {"ok": True, "run_id": run_id}

# ---------- API: read ----------
@app.get("/api/runs")
def api_runs():
    return {"runs": [dict(r) for r in list_runs()]}

@app.get("/api/runs/<run_id>/findings")
def api_run_findings(run_id):
    return {"findings": [dict(r) for r in list_findings(run_id)]}

# ---------- API: dashboard (auto-refresh) ----------
@app.get("/api/dashboard")
def api_dashboard():
    counts = dashboard_counts() or {}
    runs = list_runs(limit=20, offset=0) or []
    # zadbaj o serializowalność
    payload = {
        "counts": {
            "runs": counts.get("runs", 0),
            "latest": counts.get("latest"),
            "by_severity": counts.get("by_severity", {}),
        },
        "runs": [
            {
                "id": str(r.get("id")),
                "repo": r.get("repo"),
                "image": r.get("image"),
                "branch": r.get("branch"),
                "created_at": r.get("created_at"),
                "tool": r.get("tool"),
            }
            for r in runs
        ],
    }
    return jsonify(payload)

if __name__ == "__main__":
    # dev only; w Dockerze użyjemy waitress
    app.run(host="0.0.0.0", port=8000, debug=True)
