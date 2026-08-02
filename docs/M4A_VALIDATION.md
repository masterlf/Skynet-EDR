# M4a S2 validation floor

S2 is a deterministic, synthetic-only quality floor for the passive Hermes integration. It does not install packages, mutate a live host, contact external services, or prove compatibility with the actual Hermes dispatcher.

## Command

Run from a clean tracked checkout after dependencies are available locally:

```bash
packaging/scripts/validate-s2.sh --output /root/skynet-agent-audit/artifacts/s2
```

The absolute output must not exist. Its existing ancestor chain is opened descriptor-relatively without following symlinks and must be root/effective-UID owned and not group/other writable. The validator builds in a private mode-0700 sibling stage, verifies its device/inode/owner/mode, then atomically renames that exact inode into place; an identity drift aborts without touching the substitute. The command uses `umask 077`, private temporary state and target directories, and Cargo offline mode.

Raw gate stdout/stderr remains only in the private temporary directory and is deleted. The published report contains private `manifest.json`, `summary.json`, `metrics.tsv`, bounded fixed-schema `logs/*.log`, and `SHA256SUMS`; the checksum file does not hash itself. Before publication every allowlisted report file is size-bounded and scanned for every fixture forbidden literal plus validation leak canaries. A failure publishes no report, and CI uploads only a successfully sealed report. No database, spool, configuration, environment dump, raw fixture, or raw diagnostic is copied into it.

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
3. Runtime canary: registered callbacks and the real producer worker use live framed AF_UNIX delivery and terminal ACKs to a child daemon/current-UID allowlist, durable SQLite receipts/incidents, the real loopback Risk list/detail API, and the dashboard backend proxy. The baseline seven-rule cardinality is recorded before a dedicated synthetic-secret phase. That phase proves its fake literals exist at callback input while remaining absent from canonical producer output, plugin/fallback/daemon logs, SQLite main/WAL/SHM, persisted events/incidents, Risk list/detail responses, and the shipped Desktop `validateRiskPage` projection contract.
4. Package/VM runtime: intentionally separate release/lab gates and not run by this command.

The report therefore records `real_hermes_runtime=false` and `package_install_runtime=false`. Component or callback evidence must not be described as actual Hermes dispatcher proof.

## Gates and metrics

The command runs documentation and packaging validation, Rust format/clippy/workspace tests, Hermes Python tests, both Node suites, and dedicated corpus/producer/runtime-canary gates. Each gate records status, wall/user/system time, maximum RSS, and discovered test count.

The no-fault runtime canary counts callback-generated events independently, derives enqueued events from generated minus the producer's observed queue-drop counter, records every terminal ACK/status, reads fallback/socket/drop/backlog counters, queries durable receipts and collision evidence, and counts degraded-correlation incidents as truncations. A fault-accounting regression proves nonzero drop/collision/truncation/backlog values are preserved. It reports callback, event-to-ACK, and terminal-ACK-to-corresponding-Risk-visibility sample count/p50/p95/max. The shipped Desktop validator is executed against the live Risk response, but no misleading UI paint/projection duration is reported. Callback duration has a correctness ceiling of 50 ms. Transport, API, CPU, RSS, and store-growth observations are characterization only, not production SLOs.

## Limits

Fixtures use only clearly fake lab markers and loopback/documentation-only destinations. The canary invokes registered callbacks directly and does not exercise Hermes discovery or dispatcher ABI. It validates the shipped Desktop data contract, not browser rendering or human paint latency. One local run is not a production performance distribution. Package installation, service management, VM behavior, `cargo audit`, and `cargo deny` remain separate gates.
