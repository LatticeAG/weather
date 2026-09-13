/** weather/1 wire types (§3.1–§6.3), language-neutral JSON IDL. */

export type U = string;
export type Hash = string;
export type Sig = string;
export type Pub = string;
export type Text = string;

export type FleetID = string;   // wfl_
export type SourceID = string;  // wso_
export type WatcherID = string; // wwa_
export type DomainID = string;  // wdo_
export type SubjectID = string; // wsu_
export type KeyID = string;     // wky_
export type RequestID = string; // wrq_
export type SubscriptionID = string; // wss_
export type AlertID = string;   // wal_
export type EventID = string;   // wev_
export type PrincipalID = string; // wpr_

export type Head = { seq: U; hash: Hash };
export type Phase = "RUNNING" | "READ_ONLY" | "LOCKED";
export type Role = "reader" | "operator" | "producer" | "watcher";
export type Pin = { key_id: KeyID; public_key: Pub };
export type Principal = { id: PrincipalID; pin: Pin; roles: Role[] };
export type NativeProfile = "trellis-export/1" | "vislineage-export/1" | "weather-meter/1";
export type Native = {
  profile: NativeProfile;
  native_ref: Text;
  native_artifact: Hash;
  verification: "VERIFIED_AT_PIN" | "ASSERTED";
};
export type Observation =
  | { kind: "spend"; subject: SubjectID; delta: U; unit: "usd_micro"; usage_id: Text }
  | { kind: "scope"; subject: SubjectID; policy_hash: Hash | null; scope_hash: Hash | null; reported_violation: boolean }
  | { kind: "replication"; subject: SubjectID; processes: U | null; threads: U | null; declared_processes: U | null }
  | { kind: "pulse" }
  | { kind: "terminal" }
  | { kind: "coverage"; complete: boolean }
  | { kind: "signal"; subject: SubjectID; artifact: Hash };

export type SourceBody = {
  v: 1; fleet: FleetID; source: SourceID; seq: U; prev: Hash;
  observed_ms: U; native: Native; observation: Observation; key_id: KeyID;
};
export type SourceEntry = { body: SourceBody; hash: Hash; sig: Sig };
export type Accepted = { index: U; received_ms: U; entry: SourceEntry; late: boolean; counted: boolean };
export type SourceState = "EMPTY" | "ACTIVE" | "GAPPED" | "FORKED" | "TERMINAL" | "RETIRED";
export type SourceView = {
  source: SourceID; state: SourceState; head: Head;
  last_received_ms: U | null; complete: boolean; pending: number;
};

export type SourceConfig = {
  id: SourceID; principal: PrincipalID; pin: Pin; profile: NativeProfile;
  subjects: SubjectID[]; meter: boolean; enabled: boolean;
};
export type SubjectConfig = {
  id: SubjectID; policies: Hash[]; scopes: Hash[]; max_processes: U; max_threads: U;
};
export type WatcherConfig = {
  id: WatcherID; principal: PrincipalID; pin: Pin; domain: DomainID; enabled: boolean;
};
export type Config = {
  v: 1; fleet: FleetID; epoch: U; predecessor: Hash; effective_ms: U;
  pack: "weather-core/1.0.0"; pack_digest: Hash;
  window_ms: 60000; history_windows: 5; baseline_floor: "100000";
  spend_min: "1000000"; spend_multiplier: 3; silence_ms: 120000;
  max_late_ms: 120000; vote_ttl_ms: 180000; quorum_domains: 2;
  sources: SourceConfig[]; subjects: SubjectConfig[]; watchers: WatcherConfig[];
  principals: Principal[]; revoked_keys: KeyID[]; notification_target: "primary" | null;
};
export type ConfigEnvelope = { body: Config; hash: Hash; key_id: KeyID; sig: Sig };

export type Quality = "COMPLETE" | "INCOMPLETE" | "DEGRADED";
export type Detector = "spend_spike/1" | "scope_drift/1" | "replication_anomaly/1" | "stream_silence/1";
export type DecisionStatus = "HIT" | "CLEAR" | "UNKNOWN" | "SIGNAL";
export type Reason =
  | "SPEND_SPIKE" | "BELOW_THRESHOLD" | "BASELINE_WARMUP" | "COVERAGE_INCOMPLETE"
  | "ARITHMETIC_OVERFLOW" | "DRIFT_REPORTED" | "POLICY_DRIFT" | "SCOPE_DRIFT"
  | "SCOPE_MATCH" | "EVIDENCE_MISSING" | "PROCESS_EXCESS" | "THREAD_EXCESS"
  | "DECLARED_MISMATCH" | "INVENTORY_MATCH" | "STREAM_SILENT" | "STREAM_RECENT"
  | "SOURCE_TERMINAL" | "SIGNAL_ONLY";
export type Decision = { status: DecisionStatus; reason: Reason; value: U | null; limit: U | null };
export type SourceCut = {
  source: SourceID; head: Head; state: SourceState; activated_ms: U;
  last_received_ms: U | null; last_input: Hash | null; complete: boolean;
};
export type Manifest = {
  v: 1; fleet: FleetID; config: Hash; start_ms: U; end_ms: U;
  through_index: U; inputs: Hash[]; history: Hash[]; cuts: SourceCut[]; quality: Quality;
};
export type ResultBody = {
  v: 1; fleet: FleetID; config: Hash; manifest: Hash; detector: Detector;
  target: FleetID | SourceID | SubjectID; decision: Decision; evidence: Hash[];
};
export type Result = { body: ResultBody; hash: Hash };
export type VoteBody = {
  v: 1; fleet: FleetID; watcher: WatcherID; config: Hash; result: Hash; manifest: Hash; key_id: KeyID;
};
export type Vote = { body: VoteBody; hash: Hash; sig: Sig };

export type AlertState = "CANDIDATE" | "CORROBORATED" | "ACKNOWLEDGED" | "CLOSED" | "EXPIRED";
export type Assurance = "VALID" | "DEGRADED";
export type DeliveryState = "NONE" | "QUEUED" | "IN_FLIGHT" | "RETRY" | "DELIVERED" | "FAILED" | "CANCELLED";
export type AlertView = {
  id: AlertID; result: Hash; state: AlertState; assurance: Assurance;
  domains: DomainID[]; votes: Hash[]; expires_ms: U; delivery: DeliveryState; revision: U;
};
export type SubscriptionState = "ACTIVE" | "PAUSED" | "EXPIRED" | "CLOSED";
export type Subscription = {
  id: SubscriptionID; watcher: WatcherID; state: SubscriptionState;
  ack: U; delivered: U; lease_until_ms: U; revision: U;
};
export type PageBody = {
  v: 1; fleet: FleetID; alert: AlertID; result: Hash; config: Hash; manifest: Hash;
  corroborated: Head; semantics: "ADVISORY_ONLY"; key_id: KeyID;
};
export type Page = { body: PageBody; hash: Hash; sig: Sig };
export type Delivery = {
  alert: AlertID; state: DeliveryState; attempts: number;
  due_ms: U | null; lease_until_ms: U | null; last_status: number | null;
};

export type AuditData = {
  ConfigScheduled: { config: Hash };
  ConfigActivated: { config: Hash };
  KeysRevoked: { config: Hash; keys: KeyID[] };
  Tick: { logical_ms: U };
  SourceAccepted: { accepted: Accepted };
  SourceBuffered: { entry: SourceEntry };
  SourceForkObserved: { source: SourceID; left: SourceEntry; right: SourceEntry; reason: "SLOT_FORK" | "TERMINAL_SUFFIX" };
  WindowFinalized: { manifest: Hash; result_count: number };
  ResultFinalized: { result: Hash };
  AlertCreated: { alert: AlertView };
  VoteAccepted: { alert: AlertID; vote: Vote };
  AlertChanged: { alert: AlertID; from: AlertState; to: AlertState; actor: PrincipalID | null; note_hash: Hash | null; revision: U };
  AlertDegraded: { alert: AlertID; source: SourceID | null; key: KeyID | null; revision: U };
  SubscriptionChanged: { subscription: Subscription; event: "OPEN" | "PAUSE" | "RESUME" | "EXPIRE" | "CLOSE" };
  DeliveryChanged: { delivery: Delivery; page: Hash | null; cancel_pending: boolean };
  FleetChanged: { from: Phase; to: Phase; reason: "CAPACITY" | "OPERATOR" };
};
export type AuditKind = keyof AuditData;
export type AuditBody = {
  [K in keyof AuditData]: {
    v: 1; fleet: FleetID; event_id: EventID; seq: U; prev: Hash;
    at_ms: U; key_id: KeyID; kind: K; data: AuditData[K];
  }
}[keyof AuditData];
export type Audit = { body: AuditBody; hash: Hash; sig: Sig };

export type CheckpointBody = {
  v: 1; fleet: FleetID; head: Head; through_index: U; logical_ms: U;
  config: Hash | null; key_id: KeyID;
};
export type Checkpoint = { body: CheckpointBody; hash: Hash; sig: Sig };
export type ObjectRecord = {
  kind: "config" | "manifest" | "result" | "page"; hash: Hash;
  value: ConfigEnvelope | Manifest | Result | Page;
};
export type BundlePage = {
  v: 1; format: "weather-evidence/1"; checkpoint: Checkpoint; after_seq: U;
  entries: Audit[]; objects: ObjectRecord[]; next_seq: U; more: boolean;
  native_disclosure: "COMMITMENTS_ONLY";
};
export type VerifyResult = {
  integrity: "VALID" | "INVALID";
  replay: "MATCH" | "MISMATCH" | "INCOMPLETE";
  completeness: "AT_PIN" | "UNPINNED_PREFIX" | "INCOMPLETE";
  native_truth: "NOT_ATTESTED";
  head: Head;
  reasons: Text[];
};

export type Counts = { candidate: number; corroborated: number; acknowledged: number; closed: number; expired: number };
export type FleetView = {
  fleet: FleetID; phase: Phase; logical_ms: U; config: ConfigEnvelope | null;
  pending: ConfigEnvelope | null; head: Head; through_index: U;
  sources: SourceView[]; alerts: Counts;
  paging: "AVAILABLE" | "PAGING_UNAVAILABLE"; catching_up: boolean;
};
export type IngestItem = {
  seq: U; status: "ACCEPTED" | "DUPLICATE" | "BUFFERED" | "FORK" | "NOT_APPLIED";
  index: U | null; counted: boolean;
};
export type FramePage = { entries: Audit[]; objects: ObjectRecord[]; through: Head; next_seq: U; more: boolean };
export type MetricName =
  | "inputs_accepted_total" | "inputs_duplicate_total" | "inputs_late_total"
  | "source_forks_total" | "detector_hit_total" | "detector_unknown_total"
  | "vote_rejected_total" | "page_attempt_total" | "page_failed_total"
  | "audit_bytes" | "logical_lag_ms" | "active_domains";
export type Metric = { name: MetricName; value: U };

export type Calls = {
  "fleet.get": { input: Record<string, never>; output: FleetView };
  "config.put": { input: { config: ConfigEnvelope }; output: { hash: Hash; state: "PENDING"; effective_ms: U } };
  "source.append": { input: { entries: SourceEntry[] }; output: { items: IngestItem[]; source: SourceView } };
  "subscription.open": { input: { watcher: WatcherID; after_seq: U }; output: Subscription };
  "subscription.read": { input: { subscription: SubscriptionID; after_seq: U; limit: number }; output: FramePage };
  "subscription.ack": { input: { subscription: SubscriptionID; through_seq: U }; output: Subscription };
  "subscription.set": { input: { subscription: SubscriptionID; action: "pause" | "resume" | "close"; expected_revision: U }; output: Subscription };
  "vote.submit": { input: { vote: Vote }; output: { accepted: true; alert: AlertView } };
  "alert.list": { input: { state: AlertState | null; after: AlertID | null; limit: number }; output: { alerts: AlertView[]; next: AlertID | null } };
  "alert.get": { input: { alert: AlertID }; output: { alert: AlertView; result: Result; manifest: Manifest } };
  "alert.act": { input: { alert: AlertID; action: "ack" | "close"; expected_revision: U; note_hash: Hash | null }; output: AlertView };
  "audit.read": { input: { after_seq: U; through: Head | null; limit: number }; output: FramePage };
  "audit.checkpoint": { input: Record<string, never>; output: Checkpoint };
  "bundle.export": { input: { after_seq: U; checkpoint: Checkpoint; limit: number }; output: BundlePage };
  "metrics.get": { input: Record<string, never>; output: { fleet: FleetID; samples: Metric[] } };
};
export type Method = keyof Calls;
export type RequestBody = {
  [M in Method]: { v: 1; fleet: FleetID; id: RequestID; key_id: KeyID; sent_ms: U; method: M; params: Calls[M]["input"] }
}[Method];
export type RequestEnvelope = { body: RequestBody; hash: Hash; sig: Sig };
export type Response<M extends Method = Method> =
  | { v: 1; id: RequestID; ok: true; result: Calls[M]["output"] }
  | { v: 1; id: RequestID; ok: false; error: { code: string; retryable: boolean } };

export type HistoryWindow = { manifest: Manifest; accepted: Accepted[] };
export type ReplayInput = {
  config: ConfigEnvelope; manifest: Manifest; accepted: Accepted[];
  history: HistoryWindow[]; last_inputs: Accepted[];
};
export type ReplayOutput = { manifest: Hash; results: Result[] };
export type VerifyInput = { pages: BundlePage[]; root: Pin; audit: Pin; expected_head: Head | null };

export type PackManifest = {
  v: 1; pack: "weather-core/1.0.0"; schema_major: 1;
  semantics: "WEATHER-SPEC-2026-09-12/4.3"; corpus_digest: Hash;
  implementations: { language: "python" | "typescript"; artifact_digest: Hash }[];
};

export type Fraction = { n: U; d: U } | null;
export type Interval = { low: string; high: string } | null;
export type EvalConfig = {
  v: 1; suite: "weather-conformance/1"; pack_digest: Hash; seed: U;
  allow_seed_override: boolean; corpus_digest: Hash;
  implementations: ("typescript" | "python")[];
};
export type EvalCounts = {
  tp: U; fp: U; fn: U; tn: U; unknown_positive: U; unknown_negative: U;
  signals: U; corroborated: U; delivered: U;
};
export type EvalRate = { fraction: Fraction; wilson95: Interval };
export type EvalReport = {
  v: 1; suite: "weather-conformance/1"; corpus_digest: Hash; pack_digest: Hash;
  seed: U; implementation: "typescript" | "python"; vectors: number; passed: number;
  counts: EvalCounts; precision: EvalRate; recall: EvalRate;
  false_positive_rate: EvalRate; coverage: EvalRate;
  limitations: ["SYNTHETIC_SCOPE_ONLY", "SOURCE_ASSERTIONS_NOT_TRUTH", "COT_NOT_PROOF"];
};
export type LabeledUnit = { unit: Text; detector: Detector; positive: boolean };
export type EvalSuite = {
  v: 1; suite: "weather-conformance/1"; config: EvalConfig; units: LabeledUnit[];
};

export type ClientConfig = {
  v: 1; endpoint: string; fleet: FleetID; principal_key_file: string;
  trust_file: string; timeout_ms: number;
};
export type TrustFile = { v: 1; fleet: FleetID; root: Pin; audit: Pin; minimum_head: Head | null };
export type PrivateKeyFile = { v: 1; key_id: KeyID; public_key: Pub; seed: string };
export type BootstrapFleet = {
  fleet: FleetID; root: Pin; audit: Pin;
  allowed_view_origin: string | null; primary_url: string | null;
};
export type Bootstrap = {
  v: 1; fleets: BootstrapFleet[]; hard_bytes_per_fleet: "8589934592";
  reserve_bytes: "67108864"; storage_version: 1;
};
export type WatcherCursor = {
  v: 1; fleet: FleetID; watcher: WatcherID; subscription: SubscriptionID | null;
  ack: U; head: Head; config: Hash | null; pending_votes: Vote[];
};
export type CollectorCursor = {
  v: 1; fleet: FleetID; source: SourceID; native_frontier: Text;
  head: Head; pending_entries: SourceEntry[];
};
export type ExportHeader = { record: "header"; v: 1; format: "weather-evidence/1"; checkpoint: Checkpoint };
export type ExportChunk = { record: "page"; page: BundlePage };
export type ExportTrailer = { record: "trailer"; pages: U; entries: U; head: Head };
export type Migration = {
  v: 1; fleet: FleetID; from_storage: number; to_storage: number;
  tool_digest: Hash; input_head: Head; backup_digest: Hash; expected_projection: Hash;
};
