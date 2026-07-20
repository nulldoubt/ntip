CREATE TABLE master_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    durable_generation INTEGER NOT NULL DEFAULT 0 CHECK (durable_generation >= 0),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

INSERT INTO master_state (singleton, durable_generation, created_at)
VALUES (1, 0, unixepoch());

CREATE TABLE vnrs (
    name TEXT PRIMARY KEY
        CHECK (length(name) BETWEEN 1 AND 63),
    network INTEGER NOT NULL
        CHECK (network BETWEEN 0 AND 4294967295),
    prefix INTEGER NOT NULL
        CHECK (prefix BETWEEN 1 AND 30),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (network, prefix)
) STRICT, WITHOUT ROWID;

CREATE TRIGGER vnrs_name_immutable
BEFORE UPDATE OF name ON vnrs
BEGIN
    SELECT RAISE(ABORT, 'VNR names are immutable');
END;

CREATE TABLE nodes (
    id BLOB PRIMARY KEY CHECK (length(id) = 16),
    name TEXT NOT NULL UNIQUE
        CHECK (length(name) BETWEEN 1 AND 63),
    vnr_name TEXT NOT NULL,
    address INTEGER NOT NULL UNIQUE
        CHECK (address BETWEEN 0 AND 4294967295),
    enrollment_state TEXT NOT NULL DEFAULT 'unenrolled'
        CHECK (enrollment_state IN ('unenrolled', 'enrolled')),
    public_key BLOB
        CHECK (public_key IS NULL OR length(public_key) = 32),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    FOREIGN KEY (vnr_name) REFERENCES vnrs(name)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK ((enrollment_state = 'unenrolled' AND public_key IS NULL) OR
           (enrollment_state = 'enrolled' AND public_key IS NOT NULL))
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX nodes_public_key_unique
ON nodes(public_key) WHERE public_key IS NOT NULL;

CREATE INDEX nodes_vnr_name
ON nodes(vnr_name);

CREATE TRIGGER nodes_id_immutable
BEFORE UPDATE OF id ON nodes
BEGIN
    SELECT RAISE(ABORT, 'Node IDs are immutable');
END;

CREATE TABLE routes (
    id BLOB PRIMARY KEY CHECK (length(id) = 16),
    network INTEGER NOT NULL
        CHECK (network BETWEEN 0 AND 4294967295),
    prefix INTEGER NOT NULL
        CHECK (prefix BETWEEN 1 AND 32),
    node_id BLOB NOT NULL CHECK (length(node_id) = 16),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    FOREIGN KEY (node_id) REFERENCES nodes(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    UNIQUE (network, prefix)
) STRICT, WITHOUT ROWID;

CREATE INDEX routes_node_id
ON routes(node_id);

CREATE TABLE enrollment_credentials (
    handle BLOB PRIMARY KEY CHECK (length(handle) = 16),
    node_id BLOB NOT NULL CHECK (length(node_id) = 16),
    derived_psk BLOB,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    status TEXT NOT NULL
        CHECK (status IN ('unused', 'consumed', 'revoked')),
    consumed_at INTEGER CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    revoked_at INTEGER CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    FOREIGN KEY (node_id) REFERENCES nodes(id)
        ON UPDATE RESTRICT ON DELETE CASCADE,
    CHECK ((status = 'unused' AND length(derived_psk) = 32 AND
            consumed_at IS NULL AND revoked_at IS NULL) OR
           (status = 'consumed' AND derived_psk IS NULL AND
            consumed_at IS NOT NULL AND revoked_at IS NULL) OR
           (status = 'revoked' AND derived_psk IS NULL AND
            consumed_at IS NULL AND revoked_at IS NOT NULL))
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX enrollment_credentials_one_unused_per_node
ON enrollment_credentials(node_id) WHERE status = 'unused';

CREATE INDEX enrollment_credentials_node_created
ON enrollment_credentials(node_id, created_at DESC);

CREATE TABLE users (
    id BLOB PRIMARY KEY CHECK (length(id) = 16),
    username TEXT NOT NULL UNIQUE
        CHECK (length(username) BETWEEN 1 AND 63 AND username = lower(username)),
    role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'superuser')),
    password_phc TEXT NOT NULL CHECK (length(password_phc) BETWEEN 1 AND 512),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    password_change_required INTEGER NOT NULL DEFAULT 0
        CHECK (password_change_required IN (0, 1)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    password_changed_at INTEGER NOT NULL CHECK (password_changed_at >= created_at)
) STRICT, WITHOUT ROWID;

CREATE TABLE user_tombstones (
    username TEXT PRIMARY KEY
        CHECK (length(username) BETWEEN 1 AND 63 AND username = lower(username)),
    former_user_id BLOB NOT NULL UNIQUE CHECK (length(former_user_id) = 16),
    tombstoned_at INTEGER NOT NULL CHECK (tombstoned_at >= 0),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('local_cli', 'web', 'system')),
    actor_id BLOB CHECK (actor_id IS NULL OR length(actor_id) = 16)
) STRICT, WITHOUT ROWID;

CREATE TRIGGER user_tombstones_no_update
BEFORE UPDATE ON user_tombstones
BEGIN
    SELECT RAISE(ABORT, 'user tombstones are immutable');
END;

CREATE TRIGGER user_tombstones_no_delete
BEFORE DELETE ON user_tombstones
BEGIN
    SELECT RAISE(ABORT, 'usernames are permanently reserved');
END;

CREATE TABLE web_sessions (
    id BLOB PRIMARY KEY CHECK (length(id) = 16),
    user_id BLOB NOT NULL CHECK (length(user_id) = 16),
    token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    csrf_token_hash BLOB NOT NULL CHECK (length(csrf_token_hash) = 32),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    last_seen_at INTEGER NOT NULL CHECK (last_seen_at >= created_at),
    idle_expires_at INTEGER NOT NULL CHECK (idle_expires_at > last_seen_at),
    absolute_expires_at INTEGER NOT NULL CHECK (absolute_expires_at > created_at),
    reauthenticated_at INTEGER
        CHECK (reauthenticated_at IS NULL OR reauthenticated_at >= created_at),
    user_agent TEXT NOT NULL DEFAULT '' CHECK (length(user_agent) <= 1024),
    FOREIGN KEY (user_id) REFERENCES users(id)
        ON UPDATE RESTRICT ON DELETE CASCADE,
    CHECK (idle_expires_at <= absolute_expires_at)
) STRICT, WITHOUT ROWID;

CREATE INDEX web_sessions_user_expiry
ON web_sessions(user_id, absolute_expires_at);

CREATE INDEX web_sessions_idle_expiry
ON web_sessions(idle_expires_at);

CREATE INDEX web_sessions_absolute_expiry
ON web_sessions(absolute_expires_at);

CREATE TABLE login_throttles (
    principal_hash BLOB PRIMARY KEY CHECK (length(principal_hash) = 32),
    failure_count INTEGER NOT NULL CHECK (failure_count >= 0),
    window_started_at INTEGER NOT NULL CHECK (window_started_at >= 0),
    blocked_until INTEGER NOT NULL CHECK (blocked_until >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= window_started_at)
) STRICT, WITHOUT ROWID;

CREATE INDEX login_throttles_updated
ON login_throttles(updated_at);

CREATE TABLE settings_revisions (
    id BLOB PRIMARY KEY CHECK (length(id) = 16),
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0),
    based_on_revision INTEGER CHECK (based_on_revision IS NULL OR based_on_revision > 0),
    status TEXT NOT NULL
        CHECK (status IN ('pending_apply', 'active', 'failed', 'pending_restart')),
    failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 128),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('local_cli', 'web', 'system')),
    actor_id BLOB CHECK (actor_id IS NULL OR length(actor_id) = 16),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    applied_at INTEGER CHECK (applied_at IS NULL OR applied_at >= created_at),
    inner_mtu INTEGER NOT NULL CHECK (inner_mtu BETWEEN 576 AND 65501),
    heartbeat_seconds INTEGER NOT NULL
        CHECK (heartbeat_seconds BETWEEN 1 AND 65535),
    suspect_seconds INTEGER NOT NULL
        CHECK (suspect_seconds > heartbeat_seconds AND suspect_seconds <= 65535),
    offline_seconds INTEGER NOT NULL
        CHECK (offline_seconds > suspect_seconds AND offline_seconds <= 65535),
    default_enrollment_lifetime_seconds INTEGER NOT NULL
        CHECK (default_enrollment_lifetime_seconds BETWEEN 60 AND 2592000),
    traffic_cold_seconds INTEGER NOT NULL
        CHECK (traffic_cold_seconds BETWEEN 1 AND 65535),
    traffic_hot_packets_per_second INTEGER NOT NULL
        CHECK (traffic_hot_packets_per_second BETWEEN 1 AND 4294967295),
    traffic_hot_bits_per_second INTEGER NOT NULL
        CHECK (traffic_hot_bits_per_second > 0),
    traffic_saturated_queue_percent INTEGER NOT NULL
        CHECK (traffic_saturated_queue_percent BETWEEN 1 AND 100),
    traffic_hysteresis_seconds INTEGER NOT NULL
        CHECK (traffic_hysteresis_seconds BETWEEN 1 AND 3600),
    runtime_event_retention_days INTEGER NOT NULL
        CHECK (runtime_event_retention_days BETWEEN 1 AND 3650),
    connectivity_retention_days INTEGER NOT NULL
        CHECK (connectivity_retention_days BETWEEN 1 AND 3650),
    maximum_nodes INTEGER NOT NULL CHECK (maximum_nodes BETWEEN 1 AND 65536),
    FOREIGN KEY (based_on_revision) REFERENCES settings_revisions(revision)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK ((status = 'failed' AND failure_code IS NOT NULL) OR
           (status != 'failed' AND failure_code IS NULL)),
    CHECK ((status = 'active' AND applied_at IS NOT NULL) OR
           (status IN ('pending_apply', 'failed') AND applied_at IS NULL) OR
           status = 'pending_restart')
) STRICT, WITHOUT ROWID;

CREATE TRIGGER settings_revisions_immutable_snapshot
BEFORE UPDATE OF
    id, revision, based_on_revision, actor_kind, actor_id, created_at,
    inner_mtu, heartbeat_seconds, suspect_seconds, offline_seconds,
    default_enrollment_lifetime_seconds, traffic_cold_seconds,
    traffic_hot_packets_per_second, traffic_hot_bits_per_second,
    traffic_saturated_queue_percent, traffic_hysteresis_seconds,
    runtime_event_retention_days, connectivity_retention_days, maximum_nodes
ON settings_revisions
BEGIN
    SELECT RAISE(ABORT, 'settings revision snapshots are immutable');
END;

CREATE TRIGGER settings_revisions_no_delete
BEFORE DELETE ON settings_revisions
BEGIN
    SELECT RAISE(ABORT, 'settings revision history is immutable');
END;

INSERT INTO settings_revisions (
    id, revision, based_on_revision, status, failure_code,
    actor_kind, actor_id, created_at, applied_at,
    inner_mtu, heartbeat_seconds, suspect_seconds, offline_seconds,
    default_enrollment_lifetime_seconds,
    traffic_cold_seconds, traffic_hot_packets_per_second,
    traffic_hot_bits_per_second, traffic_saturated_queue_percent,
    traffic_hysteresis_seconds, runtime_event_retention_days,
    connectivity_retention_days, maximum_nodes
) VALUES (
    X'00000000000000000000000000000001', 1, NULL, 'active', NULL,
    'system', NULL, unixepoch(), unixepoch(),
    1380, 15, 30, 45,
    86400,
    30, 100000,
    1000000000, 80,
    5, 90,
    30, 4096
);

CREATE TABLE settings_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    desired_revision INTEGER NOT NULL,
    effective_revision INTEGER NOT NULL,
    FOREIGN KEY (desired_revision) REFERENCES settings_revisions(revision)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (effective_revision) REFERENCES settings_revisions(revision)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

INSERT INTO settings_state (singleton, desired_revision, effective_revision)
VALUES (1, 1, 1);

CREATE TABLE runtime_events (
    id BLOB PRIMARY KEY CHECK (length(id) = 16),
    kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 128),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'error')),
    node_id BLOB CHECK (node_id IS NULL OR length(node_id) = 16),
    observed_at INTEGER NOT NULL CHECK (observed_at >= 0),
    details_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
    FOREIGN KEY (node_id) REFERENCES nodes(id)
        ON UPDATE RESTRICT ON DELETE SET NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX runtime_events_observed
ON runtime_events(observed_at DESC, id);

CREATE INDEX runtime_events_node_observed
ON runtime_events(node_id, observed_at DESC) WHERE node_id IS NOT NULL;

CREATE TABLE connectivity_checks (
    id BLOB PRIMARY KEY CHECK (length(id) = 16),
    node_id BLOB CHECK (node_id IS NULL OR length(node_id) = 16),
    node_name TEXT NOT NULL CHECK (length(node_name) BETWEEN 1 AND 63),
    requested_by_kind TEXT NOT NULL CHECK (requested_by_kind IN ('local_cli', 'web', 'system')),
    requested_by_id BLOB CHECK (requested_by_id IS NULL OR length(requested_by_id) = 16),
    status TEXT NOT NULL
        CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'timed_out', 'interrupted')),
    timeout_ms INTEGER NOT NULL CHECK (timeout_ms BETWEEN 500 AND 10000),
    requested_at INTEGER NOT NULL CHECK (requested_at >= 0),
    started_at INTEGER CHECK (started_at IS NULL OR started_at >= requested_at),
    completed_at INTEGER CHECK (completed_at IS NULL OR completed_at >= requested_at),
    rtt_microseconds INTEGER CHECK (rtt_microseconds IS NULL OR rtt_microseconds >= 0),
    error_code TEXT CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
    FOREIGN KEY (node_id) REFERENCES nodes(id)
        ON UPDATE RESTRICT ON DELETE SET NULL,
    CHECK ((status IN ('queued', 'running') AND completed_at IS NULL) OR
           (status IN ('succeeded', 'failed', 'timed_out', 'interrupted') AND completed_at IS NOT NULL)),
    CHECK ((status = 'succeeded' AND rtt_microseconds IS NOT NULL AND error_code IS NULL) OR
           (status != 'succeeded' AND rtt_microseconds IS NULL))
) STRICT, WITHOUT ROWID;

CREATE INDEX connectivity_checks_requested
ON connectivity_checks(requested_at DESC, id);

CREATE INDEX connectivity_checks_node_requested
ON connectivity_checks(node_id, requested_at DESC) WHERE node_id IS NOT NULL;

CREATE TABLE audit_export_receipts (
    id BLOB PRIMARY KEY CHECK (length(id) = 16),
    exported_through_sequence INTEGER NOT NULL CHECK (exported_through_sequence > 0),
    entry_count INTEGER NOT NULL CHECK (entry_count > 0),
    content_sha256 BLOB NOT NULL CHECK (length(content_sha256) = 32),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('local_cli', 'web')),
    actor_id BLOB CHECK (actor_id IS NULL OR length(actor_id) = 16),
    exported_at INTEGER NOT NULL CHECK (exported_at >= 0)
) STRICT, WITHOUT ROWID;

CREATE INDEX audit_export_receipts_sequence
ON audit_export_receipts(exported_through_sequence DESC);

CREATE TRIGGER audit_export_receipts_no_update
BEFORE UPDATE ON audit_export_receipts
BEGIN
    SELECT RAISE(ABORT, 'audit export receipts are immutable');
END;

CREATE TRIGGER audit_export_receipts_no_delete
BEFORE DELETE ON audit_export_receipts
BEGIN
    SELECT RAISE(ABORT, 'audit export receipts are immutable');
END;

CREATE TABLE audit_entries (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE CHECK (length(id) = 16),
    occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('local_cli', 'web', 'system')),
    actor_id BLOB CHECK (actor_id IS NULL OR length(actor_id) = 16),
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
    resource_type TEXT NOT NULL CHECK (length(resource_type) BETWEEN 1 AND 128),
    resource_id TEXT NOT NULL DEFAULT '' CHECK (length(resource_id) <= 256),
    request_id BLOB CHECK (request_id IS NULL OR length(request_id) = 16),
    details_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(details_json) AND json_type(details_json) = 'object')
) STRICT;

CREATE INDEX audit_entries_occurred
ON audit_entries(occurred_at DESC, sequence DESC);

CREATE TRIGGER audit_entries_no_update
BEFORE UPDATE ON audit_entries
BEGIN
    SELECT RAISE(ABORT, 'audit entries are immutable');
END;

CREATE TRIGGER audit_entries_require_export_before_delete
BEFORE DELETE ON audit_entries
WHEN NOT EXISTS (
    SELECT 1 FROM audit_export_receipts
    WHERE exported_through_sequence >= OLD.sequence
)
BEGIN
    SELECT RAISE(ABORT, 'audit entry has not been exported');
END;

CREATE TABLE idempotency_records (
    actor_id BLOB NOT NULL CHECK (length(actor_id) = 16),
    key_hash BLOB NOT NULL CHECK (length(key_hash) = 32),
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    response_status INTEGER NOT NULL CHECK (response_status BETWEEN 100 AND 599),
    response_body BLOB NOT NULL CHECK (length(response_body) <= 65536),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    PRIMARY KEY (actor_id, key_hash)
) STRICT, WITHOUT ROWID;

CREATE INDEX idempotency_records_expiry
ON idempotency_records(expires_at);

PRAGMA user_version = 1;
