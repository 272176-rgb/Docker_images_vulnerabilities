PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,          -- uuid
  repo TEXT,
  commit_sha TEXT,
  branch TEXT,
  image TEXT,
  created_at TEXT NOT NULL      -- ISO8601
);

CREATE TABLE IF NOT EXISTS components (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  purl TEXT,
  name TEXT,
  version TEXT,
  UNIQUE (purl, name, version)
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  source TEXT NOT NULL,         -- trivy | grype
  vuln_id TEXT NOT NULL,        -- CVE-XXXX
  severity TEXT,
  cvss_score REAL,
  description TEXT,
  fix_version TEXT,
  component_id INTEGER,
  layer TEXT,
  raw_json TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
  FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_vuln ON findings(vuln_id);
