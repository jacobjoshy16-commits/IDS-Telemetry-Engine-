# Security policy

## Supported version

The current default branch is the supported development line. This reference implementation has not yet declared a stable 1.x API or long-term-support release.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this repository. Do not open a public issue containing an exploitable payload, credential, private sensor record, or sensitive network topology.

Include:

- affected version or commit;
- deployment mode and configuration relevant to the issue;
- minimal reproduction using synthetic data;
- impact and required attacker access; and
- any proposed mitigation.

Do not include production PCAPs, EVE records, Zeek logs, authentication events, passwords, tokens, or certificates.

## Deployment security notes

- The Compose OpenSearch service disables its security plugin and is for isolated local development only.
- Production OpenSearch must use TLS verification, least-privilege authentication, managed secrets, and network access controls.
- Packet capture requires elevated Linux capabilities. Keep Suricata/Zeek in a separate namespace and do not grant those capabilities to the Python engine.
- JSONL and dead-letter output can contain IP addresses, account names, detection evidence, and sensor metadata. Apply access controls and retention policies.
- Treat all sensor records as untrusted input, even when produced by an internal sensor.
