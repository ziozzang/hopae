-- Kubernetes workload principal registry (Hangang ADR 0021/0022): a durable
-- record of every workload principal Hopae authenticated, its retirement and
-- its legacy Pod-bound subjects, so a consumer whose lifecycle-feed cursor
-- expired (outbox retention) can resnapshot (`POST
-- /v1/subjects/workloads/snapshot`).
--
-- Numbered 0016: 0015 is reserved by the service-credential branch, which
-- must merge first (the runner applies versions above the recorded maximum).
CREATE TABLE workload_principals (
    position            INTEGER PRIMARY KEY AUTOINCREMENT,
    principal           TEXT NOT NULL UNIQUE CHECK (length(principal) = 68 AND substr(principal, 1, 4) = 'wk2:'),
    subject_ref         TEXT NOT NULL CHECK (length(subject_ref) = 50 AND substr(subject_ref, 1, 2) = 's_'),
    spiffe_id           TEXT CHECK (spiffe_id IS NULL OR length(spiffe_id) <= 2048),
    service             TEXT NOT NULL CHECK (length(service) BETWEEN 1 AND 128),
    cluster             TEXT NOT NULL CHECK (length(cluster) BETWEEN 1 AND 128),
    namespace           TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 63),
    service_account     TEXT NOT NULL CHECK (length(service_account) BETWEEN 1 AND 253),
    service_account_uid TEXT NOT NULL CHECK (length(service_account_uid) BETWEEN 1 AND 128),
    status              TEXT NOT NULL CHECK (status IN ('active', 'retired')),
    first_seen_at       INTEGER NOT NULL,
    last_seen_at        INTEGER NOT NULL,
    retired_at          INTEGER,
    cause               TEXT CHECK (cause IS NULL OR cause IN ('deleted', 'uid_changed')),
    replacement         TEXT CHECK (replacement IS NULL OR length(replacement) = 68),
    CHECK ((status = 'retired') = (retired_at IS NOT NULL))
) STRICT;
-- Retirement is permanent: a retired ServiceAccount incarnation never
-- becomes active again (a re-created ServiceAccount has a new principal).
CREATE TRIGGER workload_principal_retired_is_final BEFORE UPDATE OF status ON workload_principals
WHEN OLD.status = 'retired' AND NEW.status != 'retired'
BEGIN
    SELECT RAISE(ABORT, 'retired workload principal is final');
END;
CREATE TABLE workload_legacy_mappings (
    legacy_subject_ref TEXT NOT NULL CHECK (length(legacy_subject_ref) = 50),
    principal          TEXT NOT NULL REFERENCES workload_principals (principal),
    observed_at        INTEGER NOT NULL,
    PRIMARY KEY (legacy_subject_ref, principal)
) STRICT;
CREATE INDEX workload_legacy_mappings_principal ON workload_legacy_mappings (principal);
