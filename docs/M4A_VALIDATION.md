# M4a S2 validation floor

S2 is a deterministic, synthetic-only quality floor for the passive Hermes integration. It does not install packages, mutate a live host, contact external services, or prove compatibility with the actual Hermes dispatcher.

## Command

Run from a clean tracked checkout after dependencies are available locally:

```bash
packaging/scripts/validate-s2.sh --output /root/skynet-agent-audit/artifacts/s2
```

The absolute output must be a new or empty directory outside sensitive system/credential paths. Symlink components are rejected. The command uses `umask 077`, private temporary state and target directories, and Cargo offline mode. It emits private `manifest.json`, `summary.json`, `metrics.tsv`, `logs/*.log`, and `SHA256SUMS`; the checksum file does not hash itself. No database, spool, configuration, environment dump, or raw fixture is copied into the report.

## Exact live rule matrix

| Rule | Severity | Corpus/runtime expectation |
|---|---|---|
| `EDR-EXFIL-001` | Critical | sensitive read followed by reviewed egress |
| `EDR-MCP-001` | High | instructional attack followed by network-capable MCP request |
| `EDR-PI-001` | High | instructional attack followed by sensitive network tool request |
| `EDR-MSG-001` | High | instructional attack followed by sensitive delivery request |
| `EDR-NET-001` | High | instructional attack followed by explicit direct-IP process egress |
| `EDR-CRON-001` | High | instructional attack followed by an authoritative successful schedule mutation |
| `EDR-MALWARE-001` | High | exact allowlisted safe malware marker in omitted MCP output |

`EDR-CONFIG-001`, `EDR-SCOPE-001`, and `EDR-PERSIST-001` remain producer-dark. `EDR-SECRET-001` remains unsupported. They are excluded from live recall and cannot satisfy the seven-rule gate.

## Evidence levels

1. Corpus: strict versioned manifest, canonical replay, malformed/duplicate rejection, exact severity/cardinality, and forbidden-marker scans.
2. Producer: the shipped plugin module registers its real hooks; callbacks consume corpus payloads and emit canonical producer output. This is not an actual Hermes dispatcher.
3. Runtime canary: registered callbacks and the real producer worker use live framed AF_UNIX delivery and terminal ACKs to a child daemon/current-UID allowlist, durable SQLite receipts/incidents, the real loopback Risk API, and the dashboard backend proxy. Risk projections are checked against the Desktop/Risk Explorer allowlisted contract; the independent Desktop and Dashboard Node suites remain presentation tests.
4. Package/VM runtime: intentionally separate release/lab gates and not run by this command.

The report therefore records `real_hermes_runtime=false` and `package_install_runtime=false`. Component or callback evidence must not be described as actual Hermes dispatcher proof.

## Gates and metrics

The command runs documentation and packaging validation, Rust format/clippy/workspace tests, Hermes Python tests, both Node suites, and dedicated corpus/producer/runtime-canary gates. Each gate records status, wall/user/system time, maximum RSS, and discovered test count.

The no-fault runtime canary requires generated events = terminal persisted/duplicate ACKs = durable receipts, with zero queue drops, fallback records, socket failures, collisions, and truncations. It reports callback, event-to-ACK, ACK-to-API-visible, and UI projection sample count/p50/p95/max. Callback duration has a correctness ceiling of 50 ms. Transport, API, UI, CPU, RSS, and store-growth observations are characterization only, not production SLOs.

## Limits

Fixtures use only clearly fake lab markers and loopback/documentation-only destinations. The canary invokes registered callbacks directly and does not exercise Hermes discovery or dispatcher ABI. UI timing measures retrieval and projection-contract validation, not human paint latency. One local run is not a production performance distribution. Package installation, service management, VM behavior, `cargo audit`, and `cargo deny` remain separate gates.
