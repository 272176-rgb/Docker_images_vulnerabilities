CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS runs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  ci_run_id TEXT,
  repo TEXT,
  commit_sha TEXT,
  branch TEXT,
  image TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS components (
  id BIGSERIAL PRIMARY KEY,
  purl TEXT,
  name TEXT,
  version TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_components_purl_name_version
  ON components (COALESCE(purl,''), COALESCE(name,''), COALESCE(version,''));

CREATE TABLE IF NOT EXISTS findings (
  id BIGSERIAL PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  source TEXT NOT NULL,            -- 'trivy' | 'grype' | 'clair'
  vuln_id TEXT NOT NULL,           -- CVE-XXXX / GHSA-...
  severity TEXT,                   -- Critical/High/Medium/Low/...
  cvss_score NUMERIC,
  description TEXT,
  fix_version TEXT,
  component_id BIGINT REFERENCES components(id),
  layer TEXT,
  raw JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_vuln ON findings(vuln_id);
