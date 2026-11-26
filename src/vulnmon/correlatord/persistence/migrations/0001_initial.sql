-- v1 schema (originally schema.sql). The runner wraps each migration in one
-- transaction and sets user_version; migrations must not contain BEGIN/COMMIT.
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
INSERT OR IGNORE INTO metadata VALUES ('epoch', 0);
CREATE TABLE IF NOT EXISTS generations (
    id INTEGER PRIMARY KEY,
    producer TEXT NOT NULL,
    scope TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    observed_at TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    expected_count INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('staging','active','retired','incomplete')),
    UNIQUE(producer, scope, snapshot_id),
    UNIQUE(producer, scope, revision)
);
CREATE TABLE IF NOT EXISTS active_generations (
    producer TEXT NOT NULL,
    scope TEXT NOT NULL,
    generation_id INTEGER NOT NULL REFERENCES generations(id),
    PRIMARY KEY(producer, scope)
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY,
    generation_id INTEGER NOT NULL REFERENCES generations(id),
    asset_id TEXT NOT NULL,
    component_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE(generation_id, asset_id, component_id)
);
CREATE INDEX IF NOT EXISTS observations_match ON observations(ecosystem, package);
CREATE TABLE IF NOT EXISTS advisory_revisions (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE(source, advisory_id, revision)
);
CREATE TABLE IF NOT EXISTS advisory_heads (
    source TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    revision_id INTEGER NOT NULL REFERENCES advisory_revisions(id),
    PRIMARY KEY(source, advisory_id)
);
CREATE INDEX IF NOT EXISTS advisory_match ON advisory_revisions(ecosystem, package, vulnerability_id);
CREATE TABLE IF NOT EXISTS jobs (
    epoch INTEGER PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('pending','done','superseded')),
    observation_cursor INTEGER NOT NULL DEFAULT 0,
    vulnerability_cursor TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    producer TEXT NOT NULL,
    scope TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    component_id TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    applicability TEXT NOT NULL CHECK(applicability IN ('unknown','affected','not_affected','fixed')),
    priority TEXT CHECK(priority IN ('P0','P1')),
    epoch INTEGER NOT NULL REFERENCES jobs(epoch),
    UNIQUE(producer, scope, asset_id, component_id, vulnerability_id)
);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id),
    epoch INTEGER NOT NULL REFERENCES jobs(epoch),
    observation_id INTEGER NOT NULL REFERENCES observations(id),
    applicability TEXT NOT NULL,
    priority TEXT,
    reason TEXT NOT NULL,
    evidence TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    UNIQUE(finding_id, epoch)
);
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id),
    epoch INTEGER NOT NULL REFERENCES jobs(epoch),
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, epoch, event_type)
);
