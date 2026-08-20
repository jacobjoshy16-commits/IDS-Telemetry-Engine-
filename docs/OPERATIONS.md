# Operations guide

## Deployment checklist

Before deployment:

- Synchronize Suricata, Zeek, endpoint, and engine hosts with a trusted time source.
- Confirm sensors emit one JSON object per line and Zeek has `LogAscii::use_json=T`.
- Size `IDS_QUEUE_SIZE`, detector state limits, OpenSearch shards, and retention using representative traffic.
- Configure OpenSearch TLS certificate validation and least-privilege credentials.
- Put secrets in the orchestrator's secret manager, not `.env` or Compose YAML.
- Set and monitor a writable OpenSearch dead-letter path.
- Test SIGTERM drain behavior against the orchestrator's termination grace period.
- Establish ownership and expiry for detection allowlists and downstream suppressions.
- Load-test packet capture and OpenSearch separately from the Python hot-path benchmark.

## Native Python

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
cp .env.example .env
# Edit paths and OpenSearch settings.
.venv/bin/ids-telemetry run
```

The default live behavior starts at EOF. Set `IDS_SOURCE__FROM_BEGINNING=true` or use `--from-beginning` for recovery/replay. Deterministic IDs prevent duplicate OpenSearch documents, but reading a large retained sensor file can consume cluster write capacity.

## Compose

```bash
# Engine, OpenSearch, templates, dashboard
 docker compose up --build -d

# Optional packet sensors sharing one Linux network namespace
 docker compose --profile sensors up --build -d

# Inspect status and structured logs
 docker compose ps
 docker compose logs -f telemetry-engine
```

The development OpenSearch API and Dashboards ports bind to loopback. Metrics binds to all host interfaces through the published port; firewall it as needed.

The optional packet sensor namespace grants capture-related capabilities only to Suricata and Zeek. The Python engine runs as UID/GID 65532 with a read-only root filesystem, no capabilities, and `no-new-privileges`.

### Offline PCAP replay

```bash
cp suspicious-traffic.pcap data/input/replay.pcap
docker compose --profile sensors --profile replay up --build traffic-replay
```

Only replay traffic in an isolated lab. The `sensor` Compose network is separate from the application/OpenSearch network, but operators remain responsible for preventing routes to sensitive systems.

## Secured OpenSearch

The bundled node disables the security plugin for local development. For a managed or production cluster:

```bash
export IDS_OPENSEARCH__ENABLED=true
export IDS_OPENSEARCH__HOSTS='["https://search.example:9200"]'
export IDS_OPENSEARCH__USERNAME=ids_telemetry_writer
export IDS_OPENSEARCH__PASSWORD='injected-by-secret-manager'
export IDS_OPENSEARCH__VERIFY_CERTS=true
export IDS_OPENSEARCH__CA_CERTS=/run/secrets/opensearch-ca.pem
export IDS_OPENSEARCH__DEAD_LETTER_PATH=/data/output/opensearch-dead-letter.jsonl
```

The service account needs:

- create/write/index rights on `ids-telemetry-events-*`, `ids-correlation-alerts-*`, and `ids-engine-metrics-*`;
- read/search rights on the configured endpoint authentication pattern; and
- no cluster-admin or index-delete rights during normal operation.

Install templates through a separate deployment identity if the runtime role may not manage templates.

### Retention

The engine creates date-suffixed indexes but does not impose an organization-specific retention policy. Configure Index State Management separately. Alerts commonly require longer retention than raw telemetry. Before deleting source-event indexes, decide whether alert `event_ids` must remain resolvable for investigations.

## Metrics

Prometheus metrics are served on `0.0.0.0:9108` by default:

| Metric | Meaning |
|---|---|
| `ids_telemetry_events_ingested_total` | Accepted canonical records by sensor and kind |
| `ids_telemetry_parse_errors_total` | Records rejected at the sensor boundary |
| `ids_telemetry_correlation_alerts_total` | Alerts by detector and final severity |
| `ids_telemetry_auth_lookup_errors_total` | Failed auth-context searches |
| `ids_telemetry_event_processing_seconds` | Correlation and dispatch latency histogram |
| `ids_telemetry_ingest_queue_depth` | Normalized records awaiting the consumer |
| `ids_telemetry_build_info` | Service/version identity |

The engine also emits `engine.metric` snapshots to JSON/OpenSearch at a configurable interval. This gives SIEM-only deployments structured counters even without Prometheus scraping.

Recommended alarms:

- any sustained parse-error increase;
- auth lookup errors above zero;
- queue depth continuously rising or near capacity;
- OpenSearch dead-letter file growth;
- missing metric snapshots / scrape target down;
- correlation alert count suddenly dropping to zero while ingest remains normal;
- detector state eviction (wire the detector counters to local metrics if cardinality monitoring is required).

## Dead-letter recovery

A dead-letter line contains `target_index`, `error`, and the canonical `document`. The Compose deployment stores output in the `engine-output` named volume; copy it out before recovery:

```bash
docker compose cp telemetry-engine:/data/output/opensearch-dead-letter.jsonl \
  data/output/opensearch-dead-letter.jsonl
```

Resolve the cluster/mapping problem first, then re-index with the original event ID:

```bash
jq -c '{index:{_index:.target_index,_id:.document.event_id}}, .document' \
  data/output/opensearch-dead-letter.jsonl \
  > /tmp/recovery.bulk
curl --fail --cacert "$CA" -u "$USER:$PASSWORD" \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary @/tmp/recovery.bulk \
  https://search.example:9200/_bulk
```

Review the bulk response's `errors` and item statuses before archiving the dead-letter file. The example places credentials in environment variables for brevity; prefer a protected credential helper.

## Replay and validation

```bash
ids-telemetry validate suricata /logs/eve.json
ids-telemetry validate zeek-conn /logs/conn.log
ids-telemetry validate zeek-dns /logs/dns.log

ids-telemetry replay \
  --suricata /logs/eve.json \
  --zeek-conn /logs/conn.log \
  --zeek-dns /logs/dns.log \
  --endpoint-auth /logs/auth.jsonl \
  --output /analysis/results.jsonl
```

Replay performs a k-way timestamp merge. Each source file must already be internally sorted. Use `--rate N` to limit replay speed when exercising an external cluster.

## Benchmarking

```bash
python scripts/benchmark.py \
  --events 100000 \
  --warmup 5000 \
  --assert-eps 5000 \
  --json-output /tmp/benchmark.json
```

The benchmark includes JSON decode, Pydantic model creation, dedup checks, event-time window updates, and scoring. It excludes file reads and OpenSearch I/O. Run it with the same CPU quota and Python version as production, then run a separate full pipeline test with realistic index mappings and shard topology.

## Troubleshooting

### No alerts during replay

1. Confirm `validate` reports valid records.
2. Verify timestamps are timezone-aware and files are internally sorted.
3. Check that a sequence reaches detector minimum count within the configured window.
4. Inspect destination key consistency for beaconing and root-domain grouping for DNS.
5. Ensure a domain is not allowlisted.
6. Temporarily include normalized events in JSON output to verify canonical values.

### Engine waits with "source is not present"

This is expected for a live follower when a configured sensor log has not been created. Verify the mount/path and container permissions. In Compose, start the `sensors` profile or remove unused source configuration.

### OpenSearch writes fail

- Check cluster health and disk watermarks.
- Verify the runtime role and index pattern.
- Compare the failing document against the strict template.
- Verify CA path, hostname, and system clock.
- Inspect the dead-letter error before attempting recovery.

### Elevated parse errors after sensor upgrade

Save sanitized rejected examples, compare field types and sentinels with parser tests, then update the explicit adapter and fixtures. Do not weaken canonical models to accept arbitrary extra fields.

### High memory or evictions

Reduce source cardinality upstream, investigate scan/flood behavior, and review `max_keys`, `max_events_per_key`, `max_total_events`, and context capacities. Raising limits without a memory measurement can trade detection recall for process failure.
