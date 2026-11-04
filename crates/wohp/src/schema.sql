-- WOHP core identity database. Ages are inclusive thresholds, never birth dates.
CREATE TABLE deployment (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    environment TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    evidence_class TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    audience TEXT NOT NULL,
    lookup_key_identity BLOB NOT NULL CHECK (length(lookup_key_identity) = 32)
) STRICT;

-- One row per person, whatever their age: deduplication serves every client.
CREATE TABLE humans (
    subject TEXT PRIMARY KEY CHECK (length(subject) = 43),
    lookup_key BLOB NOT NULL UNIQUE CHECK (length(lookup_key) = 32),
    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    authentication_epoch INTEGER NOT NULL CHECK (authentication_epoch >= 1),
    verified_at INTEGER NOT NULL CHECK (verified_at >= 0),
    valid_until INTEGER NOT NULL CHECK (valid_until > verified_at),
    age_at_least INTEGER CHECK (age_at_least IN (13, 14, 16, 18)),
    age_valid_until INTEGER,
    created_at INTEGER NOT NULL,
    CHECK ((age_at_least IS NULL) = (age_valid_until IS NULL))
) STRICT;

-- A relying party and its own minimum age; NULL: deduplication only.
CREATE TABLE clients (
    client_id TEXT PRIMARY KEY,
    application_scope TEXT NOT NULL UNIQUE,
    minimum_age INTEGER CHECK (minimum_age IN (13, 14, 16, 18))
) STRICT;

-- Audit of client registrations and of every change of their minimum age.
CREATE TABLE client_events (
    id INTEGER PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    event TEXT NOT NULL CHECK (event IN ('REGISTERED', 'MINIMUM_AGE_CHANGED')),
    minimum_age INTEGER CHECK (minimum_age IN (13, 14, 16, 18)),
    occurred_at INTEGER NOT NULL
) STRICT;

-- `minimum_age` is the requesting client's, fixed when the challenge is issued:
-- evidence below it is refused before anything about the person is stored.
CREATE TABLE challenges (
    id TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    audience TEXT NOT NULL,
    target_subject TEXT REFERENCES humans(subject),
    target_epoch INTEGER,
    minimum_age INTEGER CHECK (minimum_age IN (13, 14, 16, 18)),
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1)),
    CHECK ((target_subject IS NULL) = (target_epoch IS NULL))
) STRICT;

CREATE TABLE security_events (
    id INTEGER PRIMARY KEY,
    subject TEXT NOT NULL REFERENCES humans(subject),
    event TEXT NOT NULL CHECK (event IN ('ENROLLED', 'RECOVERED', 'REVOKED', 'AUTHENTICATORS_RESET')),
    occurred_at INTEGER NOT NULL
) STRICT;

CREATE TABLE client_subjects (
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    profile_subject TEXT NOT NULL REFERENCES humans(subject),
    subject TEXT NOT NULL UNIQUE CHECK (length(subject) = 43),
    PRIMARY KEY (client_id, profile_subject)
) STRICT;

PRAGMA user_version = 5;
