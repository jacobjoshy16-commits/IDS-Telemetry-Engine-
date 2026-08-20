# Detection engineering

The detectors are behavioral analytics, not signatures. Their evidence fields expose all major features so analysts can explain, tune, and test a result.

## C2 beaconing

- **Input:** canonical Zeek connection events
- **Key:** `(src_ip, dst_ip, dst_port, transport)`
- **Default window:** 900 seconds
- **Default minimum:** 8 connections
- **ATT&CK:** T1071 Application Layer Protocol

DNS destination port 53 is excluded because DNS has a dedicated detector. Multicast, unspecified, and self-directed endpoints are also excluded.

For ordered timestamps `t[0] ... t[n]`, positive inter-arrival times are:

```text
interval[i] = t[i+1] - t[i]
```

The detector calculates:

- median interval `m`;
- median absolute jitter ratio `median(|interval - m|) / m`;
- coefficient of variation `population_stdev(interval) / mean(interval)`;
- ratio of intervals inside `m ± configured_jitter`; and
- a sample-size factor that saturates at twice the minimum event count.

The default weighted score is:

```text
0.40 * jitter_component
+ 0.30 * variation_component
+ 0.20 * in_band_ratio
+ 0.10 * sample_component
```

The median period must be between 5 and 600 seconds and the score must be at least 0.68. These defaults detect both nearly fixed intervals and malware that introduces bounded jitter. A key enters a 600-second event-time cooldown after alerting.

### Beacon evidence

- `connection_count`
- `interval_count`
- `median_interval_seconds`
- `median_absolute_jitter_ratio`
- `coefficient_of_variation`
- `intervals_within_jitter_band_ratio`
- `mean_payload_bytes`
- `detector_score`

### Beacon tuning

Increase `min_events` and `minimum_score` for noisy egress networks. Reduce `max_jitter_ratio` when fixed-frequency services dominate. The detector intentionally does not decide whether an IP is internal; filter or route monitored boundaries appropriately.

Common benign periodic sources include software updates, monitoring agents, push notification services, NTP-like custom protocols, certificate checks, and health probes. Suppression should use reviewed destination/service allowlists upstream or a downstream alert rule; do not globally widen the jitter threshold to hide a known service.

## DNS tunneling

- **Input:** canonical Zeek DNS events
- **Key:** `(src_ip, best-effort registrable_domain)`
- **Default window:** 300 seconds
- **Default minimum:** 12 queries
- **ATT&CK:** T1071.004 DNS and T1048 Exfiltration Over Alternative Protocol

For every query, the detector extracts the longest label before the grouped root domain and calculates Shannon entropy:

```text
H(label) = -sum(p(character) * log2(p(character)))
```

Window features are:

- long-query/encoded-label ratio;
- high-entropy encoded-label ratio;
- unique full-query ratio;
- query rate normalized to a configured threshold;
- suspicious QTYPE ratio (`TXT`, `NULL`, type 10/16); and
- negative response ratio (`NXDOMAIN` / `SERVFAIL`).

The default weighted score is:

```text
0.27 * long_ratio
+ 0.25 * entropy_ratio
+ 0.20 * unique_ratio
+ 0.18 * rate_component
+ 0.10 * max(suspicious_qtype_ratio, 0.5 * negative_response_ratio)
```

The default threshold is 0.67. Reverse lookup zones, `windows.com`, and explicitly configured domains are allowlisted. Matching uses exact domain or label-boundary suffix, never arbitrary string suffix.

### DNS evidence

- `root_domain`
- `query_count` and `queries_per_minute`
- average query and maximum label length
- average label entropy
- long/high-entropy/unique query ratios
- suspicious QTYPE and negative-response ratios
- `detector_score`

### DNS tuning

CDNs, endpoint security products, DKIM, service discovery, anti-abuse challenges, and telemetry uploaders can produce long unique DNS names. Start by reviewing domain-specific feature distributions and adding narrow allowlist entries. Do not allowlist a public suffix.

The built-in root-domain helper is deterministic and dependency-free but is not a complete Public Suffix List implementation. Environments with many country-code domains should normalize eTLD+1 before ingestion or extend the suffix table under test.

## Cross-source risk enrichment

The network candidate's source and destination IPs define the context set. Suricata context uses the general context window (default ±600 seconds); authentication uses its own default ±900-second window.

Risk adjustments are intentionally simple and visible:

- one or more failed auth events: `+0.10` confidence and one severity level;
- any related Suricata event: `+0.05` confidence;
- a related Suricata severity 1 or 2 event: one severity level.

Severity is capped at `critical`, confidence at `1.0`. Context is evidence, not proof of causality. Analysts should examine event time, endpoint identity, NAT, DHCP, VPN, and shared resolver effects.

## ATT&CK and NIST mapping semantics

Every alert embeds mapping objects rather than only text tags:

```json
{
  "mitre_attack": [
    {
      "technique_id": "T1071.004",
      "name": "Application Layer Protocol: DNS",
      "tactic": "Command and Control",
      "url": "https://attack.mitre.org/techniques/T1071/004/"
    }
  ],
  "nist_controls": [
    {
      "control_id": "SC-7",
      "name": "Boundary Protection",
      "rationale": "Observes and correlates traffic crossing managed network boundaries."
    },
    {
      "control_id": "SI-4",
      "name": "System Monitoring",
      "rationale": "Continuously monitors network communications and analyzes detected events."
    }
  ]
}
```

A technique mapping expresses what the analytic is designed to observe. It does not assert that every alert is malicious. A NIST mapping shows how telemetry supports a control objective; it is not evidence that the organization has fully implemented or assessed that control.

## Validation workflow

For every tuning change:

1. Add a minimal malicious/suspicious sequence fixture.
2. Add a representative benign sequence that must remain below threshold.
3. Assert feature values, not only that an alert exists.
4. Replay mixed sources to verify timestamp ordering and enrichment.
5. Run the EPS benchmark to detect accidental hot-path regressions.
6. Record environment-specific threshold rationale and suppression ownership.

The bundled fixtures use reserved documentation networks and are safe to publish. They are synthetic and are not a substitute for a site-specific baseline.
