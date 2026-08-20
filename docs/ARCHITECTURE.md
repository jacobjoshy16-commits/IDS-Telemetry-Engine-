# Architecture

## Design goals

The engine is organized around five operational properties:

1. **Reject ambiguity at the trust boundary.** Raw JSON is explicitly converted before strict canonical models are constructed.
2. **Use event time for detection.** Sensor timestamps, not ingestion scheduling, determine windows and correlation ranges.
3. **Bound every hot-path queue and state table.** Backpressure and LRU capacity limits turn overload into visible degradation rather than unbounded memory growth.
4. **Keep detection available during context-store failure.** OpenSearch authentication enrichment may fail without suppressing the network detection.
5. **Make output explainable and idempotent.** Alerts contain contributing IDs and statistics; deterministic IDs make replay safe.

## Components

### Parser boundary

`src/ids_telemetry/parsers` treats sensor data as untrusted. The normalizers:

- require a JSON object rather than accepting arbitrary JSON;
- parse timestamps into timezone-aware UTC `datetime` values;
- parse IP addresses with `ipaddress` and enforce the port range;
- explicitly convert Zeek's `-` / `(empty)` sentinels;
- normalize protocol and DNS names;
- reject a record as a `ParseError` when a required field cannot be represented; and
- derive a BLAKE2 deterministic event ID from stable sensor fields.

The resulting Pydantic models use `strict=True`, `extra="forbid"`, `frozen=True`, and `validate_default=True`. Sensor dictionaries are not passed downstream and arbitrary raw records are not embedded in output.

Canonical event kinds are:

- `suricata.alert`
- `zeek.conn`
- `zeek.dns`
- `endpoint.auth`
- `correlation.alert`
- `engine.metric`

`ids-telemetry schema telemetry` and `ids-telemetry schema alert` expose their JSON Schemas.

### Ingestion and backpressure

One follower coroutine runs per configured live source. A regular-file `readline` does not block waiting for input; at EOF the task yields for the configured polling interval. The follower compares inode and file size to detect rename/create and copy-truncate rotation.

Normalized events enter one bounded `asyncio.Queue` (`IDS_QUEUE_SIZE`, default 20,000). Producers await `put` when it is full, so filesystem offsets stop advancing until the consumer recovers. This provides backpressure instead of allocating an unbounded buffer.

Offline replay assumes each individual source is timestamp sorted and performs a k-way heap merge. This preserves event-time order without loading complete files into memory.

### Correlation state

The single correlation consumer makes detector mutation race-free. Both behavioral detectors use `KeyedSlidingWindow`, which has four independent limits:

- maximum event-time span;
- maximum LRU keys;
- maximum records per key; and
- maximum total records across keys.

Cooldown tables and Suricata/auth context indexes are also LRU bounded. Capacity eviction can reduce detection history under cardinality attacks, but memory remains finite. These values are Pydantic-validated and available through nested detector settings.

The window maintains a high-water timestamp. An event older than one complete window behind that watermark is counted as late and ignored by that detector. Events still within the accepted range are inserted in timestamp order. Production pipelines should nevertheless keep sensor clocks synchronized and monitor late/eviction counters when exposing them to an external metrics system.

### Candidate enrichment

A detector first emits an internal `DetectionCandidate`. Only then does the engine perform potentially expensive context work:

1. Retrieve recent Suricata alerts indexed under either endpoint IP.
2. Retrieve in-process authentication events indexed by `host_ip` and `source_ip`.
3. Query the configured OpenSearch auth index for matching `host.ip`, `source.ip`, or `client.ip` values in the candidate window.
4. Deduplicate auth records by canonical event ID.
5. Add a confidence boost for failed authentication context.
6. Raise severity for failed authentication or high-priority Suricata context.
7. Materialize a strict `CorrelationAlert` with evidence and mappings.

OpenSearch query exceptions are caught at this boundary. The base network alert still emits, an error metric increments, and structured logs preserve the failure reason without including credentials.

### Output

The output router has document-specific behavior:

| Document | JSONL/stdout | OpenSearch |
|---|---:|---:|
| Normalized event | Configurable (off by default) | Yes when enabled |
| Correlation alert | Always | Yes when enabled |
| Metric snapshot | Configurable | Yes when enabled |

The OpenSearch sink uses a second bounded queue and batches documents by size or flush deadline. Retries use bounded exponential delay. IDs are used as OpenSearch `_id`, so retrying the complete batch or replaying source files overwrites rather than duplicates a document.

After retries are exhausted, the Compose deployment appends failed operations to `/data/output/opensearch-dead-letter.jsonl`. A dead-letter entry includes failure time, target index, error, and canonical document. If no dead-letter path is configured, the sink emits an error and increments `failed_documents`; alerts still exist in the JSON output path.

## Concurrency and lifecycle

```text
file follower(s) ──> bounded ingest queue ──> one correlation consumer
                                                   │
                                                   ├──> JSON output
                                                   └──> bounded bulk queue ──> OpenSearch
metric snapshot task ──────────────────────────────┘
```

The single consumer is intentional: detector state requires no locks and event order is deterministic. OpenSearch HTTP calls from the auth adapter and bulk sink run in worker threads via `asyncio.to_thread`, so synchronous client I/O does not block all coroutines.

On SIGINT or SIGTERM, the live daemon:

1. stops followers;
2. drains the normalized ingest queue;
3. stops the consumer;
4. cancels periodic metric snapshots;
5. flushes and closes the OpenSearch bulk worker; and
6. closes local output and the OpenSearch client.

A sink failure propagates out of the consumer rather than being silently ignored.

## Index model

Daily indexes are selected from canonical document type and `observed_at`, not wall-clock ingestion time. This keeps historical replay in its source date and supports deterministic retention:

```text
ids-telemetry-events-YYYY.MM.DD
ids-correlation-alerts-YYYY.MM.DD
ids-engine-metrics-YYYY.MM.DD
```

Templates use strict top-level mappings. Detection `evidence`, counters, and gauges permit dynamic children because detector-specific numeric features are intentionally extensible. Nested ATT&CK, NIST, Suricata, and auth objects retain their relationships.

## Trust boundaries

| Boundary | Primary controls |
|---|---|
| Sensor JSON to process | Explicit conversion, max field lengths, strict/forbid schemas |
| Packet sensors | Separate shared sensor namespace; engine has no packet-capture capabilities |
| Engine to OpenSearch | TLS/CA and credentials supported; passwords use `SecretStr`; bulk bounds/retries |
| Engine output | No raw input; structured canonical fields; deterministic IDs |
| Container runtime | Non-root engine, read-only root filesystem, all capabilities dropped, `no-new-privileges` |

The local Compose OpenSearch deployment disables authentication and is only a development convenience. A production deployment must use TLS, authentication, role-restricted index permissions, and managed secrets.

## Known trade-offs

- Registrable-domain extraction uses a small built-in list for common multi-label suffixes, not the live Public Suffix List. Add an environment-specific preprocessing layer when exact eTLD+1 grouping is required.
- Source records within one replay file are expected to be sorted.
- Correlation is process-local. Horizontal replicas must partition consistently by detector key or use an external state store; naively sending the same stream to several replicas splits windows.
- Capacity eviction favors recently active keys. Eviction protects availability but can lower recall during extreme cardinality events.
- The benchmark isolates the Python hot path. Filesystem, packet capture, network, and OpenSearch cluster sizing need separate load tests.
