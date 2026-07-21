CREATE TABLE enrollment_bootstraps (
    locator TEXT PRIMARY KEY
        CHECK (length(locator) = 8 AND
               locator NOT GLOB '*[^ABCDEFGHJKLMNPQRSTUVWXYZ23456789]*'),
    node_id BLOB NOT NULL CHECK (length(node_id) = 16),
    enrollment_handle BLOB NOT NULL UNIQUE CHECK (length(enrollment_handle) = 16),
    derivation_version INTEGER NOT NULL CHECK (derivation_version = 1),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL
        CHECK (expires_at > created_at AND expires_at <= created_at + 86400),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked', 'consumed')),
    first_redeemed_at INTEGER
        CHECK (first_redeemed_at IS NULL OR
               (first_redeemed_at >= created_at AND first_redeemed_at < expires_at)),
    failed_attempt_count INTEGER NOT NULL DEFAULT 0
        CHECK (failed_attempt_count BETWEEN 0 AND 10),
    failure_window_started_at INTEGER
        CHECK (failure_window_started_at IS NULL OR failure_window_started_at >= created_at),
    locked_until INTEGER
        CHECK (locked_until IS NULL OR
               (failure_window_started_at IS NOT NULL AND
                locked_until >= failure_window_started_at)),
    invalidated_at INTEGER
        CHECK (invalidated_at IS NULL OR invalidated_at >= created_at),
    invalidation_reason TEXT
        CHECK (invalidation_reason IS NULL OR invalidation_reason IN (
            'replaced', 'explicit_revoke', 'reset', 'node_deleted',
            'restore', 'protocol_consumed'
        )),
    CHECK ((failed_attempt_count = 0 AND failure_window_started_at IS NULL AND locked_until IS NULL) OR
           (failed_attempt_count > 0 AND failure_window_started_at IS NOT NULL)),
    CHECK ((status = 'active' AND invalidated_at IS NULL AND invalidation_reason IS NULL) OR
           (status = 'revoked' AND invalidated_at IS NOT NULL AND
            invalidation_reason IN ('replaced', 'explicit_revoke', 'reset', 'node_deleted', 'restore')) OR
           (status = 'consumed' AND invalidated_at IS NOT NULL AND
            invalidation_reason = 'protocol_consumed'))
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX enrollment_bootstraps_one_active_per_node
ON enrollment_bootstraps(node_id) WHERE status = 'active';

CREATE INDEX enrollment_bootstraps_node_created
ON enrollment_bootstraps(node_id, created_at DESC);

CREATE INDEX enrollment_bootstraps_expiry
ON enrollment_bootstraps(expires_at) WHERE status = 'active';

CREATE TRIGGER enrollment_bootstraps_identity_immutable
BEFORE UPDATE OF locator, node_id, enrollment_handle, derivation_version, created_at, expires_at
ON enrollment_bootstraps
BEGIN
    SELECT RAISE(ABORT, 'bootstrap invitation identity is immutable');
END;

CREATE TRIGGER enrollment_bootstraps_no_delete
BEFORE DELETE ON enrollment_bootstraps
BEGIN
    SELECT RAISE(ABORT, 'bootstrap locators are permanently reserved');
END;

PRAGMA user_version = 2;
