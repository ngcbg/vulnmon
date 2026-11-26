# Development baseline — first vertical slice

Implementation baseline: [architecture v0.2](https://github.com/ngcbg/vulnmon/blob/41aa16d0aa3b54e92bbcb985f772424c30bfb3bf/ARCHITECTURE.md). The current [architecture v0.3](ARCHITECTURE.md) is a proposed revision; this prototype has not yet been reconciled with its requirements. This is an offline fixture prototype, not a monitoring service or a release. No real alerts, network access, LLM calls or production inventory collection occur.

## Run from a checkout

Requirements: Ubuntu/Linux, Python 3.11+, dpkg. The implementation has no third-party runtime Python dependencies. Setuptools >=68 is a build-time dependency if installing the package. The loaded SQLite runtime must be verified against the Ubuntu security/backport status before any production deployment.

```sh
export PYTHONPATH=src
db=$(mktemp -d)/state.db
python3 -m vulnmon.cli --db "$db" init
python3 -m vulnmon.cli --db "$db" ingest-inventory tests/fixtures/inventory.json
python3 -m vulnmon.cli --db "$db" ingest-advisory tests/fixtures/advisory.json
python3 -m vulnmon.cli --db "$db" correlate --max-batches 10
python3 -m vulnmon.cli --db "$db" findings
python3 -m vulnmon.cli --db "$db" events
python3 -m unittest discover -s tests -v
```

### Ubuntu test container

Non-Ubuntu hosts lack `dpkg` and `python3-apt`, so Debian-matching tests are skipped there. Run the suite in an Ubuntu 24.04 container (system Python 3.12, dpkg, python3-apt) matching CI; podman is preferred, docker is used as a fallback. The checkout is mounted read-only and the container has no network.

```sh
contrib/dev/test-ubuntu.sh                       # full unittest discovery
contrib/dev/test-ubuntu.sh python3 -m unittest tests.test_core -v
```

The synthetic fixture describes an affected fictional Ubuntu package with a provisional P0. A fixed build is not a production-verified remediation. CLI JSON output is a development interface; the outbox is evidence of event creation, not a notification delivery queue with consumer leases yet.

## Architectural boundaries

| Requirement | First slice | Deferred |
|---|---|---|
| DB-01 | Exclusive advisory process lock and core-owned connection | Long-running sole writer with authenticated UNIX IPC and read-only query connections |
| DB-02 | 500-row staging batches, bounded reconciliation calls, compute outside write transactions | Priority scheduler, urgent admission, fairness/backpressure and latency instrumentation |
| DB-03 | Snapshot generations, atomic activation + durable job, revision checks, interrupted staging retry | Delta protocol, authoritative coverage validation, incremental jobs and new-exposure assessment while staging |
| DB-04 | WAL/FULL, foreign keys, timeout, paginated output | Concurrent bounded read-only transactions, checkpoint metrics, independent watchdog, backup/restore |
| DB-05 | Explicit domain persistence interface and packaged SQL | Schema migrations beyond v1 and alternative backend |

All CLI commands take the exclusive local lock, including reads. This is a deliberate temporary limitation: it makes the first slice auditable, but is not the production concurrency model. Do not use it as a daemon or run it on shared filesystems. A lock failure is an explicit retryable operational error. Do not access the database with external writers.

## Contract semantics

- Full snapshots only, scoped by producer and scope, with monotonically increasing revision and immutable snapshot ID. A complete snapshot's component list is the producer's assertion of coverage, not independently verified coverage. Incomplete snapshots are recorded but never activated. Identical retries are idempotent; interrupted staging can be retried with identical input. No inventory generator is included.
- Component instance IDs are stable within asset and producer/scope; they must not incorporate versions. Source package names are used for Debian package matching when supplied.
- Advisory source, advisory ID and revision identify an immutable normalized revision. The fixture producer supplies a stable vulnerability ID. Multi-vulnerability advisories, aliases, raw evidence and source checkpoints are deferred.
- The special source ubuntu-fixture is trusted only as local synthetic input; never grant that authority to remote content. The normalized affected claim asserts all builds in the given release/architecture and version range are affected; absent lower bound means no lower bound, absent fixed version means no known upper bound. Unrecognized sources, unmatched release/origin/architecture, invalid versions and conflicting claims return unknown.
- Manual boundary validation implements the current fixture subset; JSON Schemas describe the wire shape and are not independently executed at runtime. Source-specific semantics and duplicate checks are additional constraints.
- Policy fixture-policy-v1 is deliberately illustrative, not the approved organizational severity policy. Unknown findings remain visible, and a plausible emergency can receive P0. No SLA clocks or verified closure are implemented.
- Every accepted material input increments the global revision and enqueues reconciliation atomically. The offline worker processes the newest revision in bounded keyset pages; obsolete pending jobs are marked superseded. Stale findings remain visible, never silently disappear or become verified closed. Removal/disposition, selective matching, retention and source precedence are deferred.
- Decisions and outbox events commit with finding updates; an interrupted batch rolls back with its cursor. The outbox is append-only until delivery semantics are designed. No claim of exactly-once external delivery.

## Next increment

Implement an authenticated local core service, bounded priority-aware scheduler and separate read-only query path; then incremental correlation, immutable raw evidence and production Ubuntu adapters. Add finding and event contracts, migrations, durable notification leases/retries, independent health checks and point-in-time replay before live alerting. Run fault-injection and representative storage/load tests on the target VM.

Reserved modules are intentionally importable packages with no runtime behaviour. Web UI, systemd services and external inventory production remain outside this increment.
