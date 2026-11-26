"""Single-node persistence owned by the core identity (architecture v0.3 §9.2).

Every bounded unit of work acquires the exclusive advisory writer lock, opens a
fresh connection, and closes both before returning. No lock or connection is
held across units, so other core invocations (e.g. urgent work) can interleave
between staging and reconciliation batches. Work that spans units revalidates
its preconditions when it commits.
"""
from contextlib import contextmanager
from importlib.resources import files
import fcntl
import json
from pathlib import Path
import re
import sqlite3
import time

from vulnmon.common.contracts import ContractError, canonical, digest
from .interface import StaleBatch

BATCH_SIZE = 500
LOCK_POLL_SECONDS = 0.05
MIGRATION_NAME = re.compile(r"(\d{4})_[a-z0-9_]+\.sql")
TRANSACTION_CONTROL = re.compile(r"^\s*(BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE)\b",
                                 re.IGNORECASE | re.MULTILINE)


class LockTimeout(RuntimeError):
    """The writer lock was not obtained within the bounded wait; retry later."""


class SchemaMismatch(RuntimeError):
    pass


def load_migrations(source=None):
    """Return [(version, name, sql)] with contiguous versions starting at 1."""
    source = source or files(__package__).joinpath("migrations")
    found = []
    for item in source.iterdir():
        match = MIGRATION_NAME.fullmatch(item.name)
        if match is None:
            continue
        sql = item.read_text(encoding="utf-8")
        if TRANSACTION_CONTROL.search(sql):
            raise SchemaMismatch(f"migration {item.name} must not control transactions")
        found.append((int(match.group(1)), item.name, sql))
    found.sort()
    if [version for version, _, _ in found] != list(range(1, len(found) + 1)):
        raise SchemaMismatch("migration versions must be contiguous from 0001")
    return found


@contextmanager
def _transaction(db):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


class Store:
    def __init__(self, path, *, lock_timeout=5.0, migrations=None):
        self.path = Path(path).resolve()
        self.lock_path = Path(str(self.path) + ".writer.lock")
        self.lock_timeout = lock_timeout
        self.migrations = load_migrations(migrations)
        self.schema_version = len(self.migrations)
        # Test hook: called after each unit has released its connection and lock.
        self.after_unit = None

    # -- units of work -----------------------------------------------------

    @contextmanager
    def unit(self, *, migrating=False):
        """One bounded unit: exclusive lock + fresh connection, both released on exit."""
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Never unlink the lock file: concurrent processes could lock different inodes.
        lock = open(self.lock_path, "a", encoding="utf-8")
        db = None
        try:
            self._acquire(lock)
            db = sqlite3.connect(self.path, isolation_level=None, timeout=5)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA busy_timeout=5000")
            if db.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                raise RuntimeError("WAL unavailable")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > self.schema_version:
                raise SchemaMismatch(
                    f"database schema {version} is newer than supported {self.schema_version}")
            if not migrating and version != self.schema_version:
                raise SchemaMismatch(
                    f"database schema {version}, expected {self.schema_version}; run init")
            yield db
        finally:
            try:
                if db is not None:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    db.close()
            finally:
                lock.close()
        if self.after_unit is not None:
            self.after_unit()

    def _acquire(self, lock):
        # Bounded polling: flock(2) gives no fairness or timeout guarantees.
        deadline = time.monotonic() + self.lock_timeout
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LockTimeout("core writer lock busy; retry later") from None
                time.sleep(min(LOCK_POLL_SECONDS, remaining))

    def migrate(self):
        with self.unit(migrating=True) as db:
            start = current = db.execute("PRAGMA user_version").fetchone()[0]
            for version, name, sql in self.migrations[current:]:
                # executescript cannot be parameterized; version is an int from the file name.
                try:
                    db.executescript(
                        f"BEGIN IMMEDIATE;\n{sql}\n;PRAGMA user_version = {version:d};\nCOMMIT;")
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
                current = version
        return {"from": start, "to": current}

    # -- shared helpers ----------------------------------------------------

    @staticmethod
    def _epoch(db):
        return db.execute("SELECT value FROM metadata WHERE key='epoch'").fetchone()[0]

    def _enqueue(self, db):
        epoch = self._epoch(db) + 1
        db.execute("UPDATE metadata SET value=? WHERE key='epoch'", (epoch,))
        db.execute("INSERT INTO jobs(epoch,status) VALUES (?,'pending')", (epoch,))
        return epoch

    def epoch(self):
        with self.unit() as db:
            return self._epoch(db)

    # -- inventory ---------------------------------------------------------

    def ingest_inventory(self, snapshot):
        producer, scope = snapshot["producer"], snapshot["scope"]
        revision = snapshot["revision"]
        payload_hash = digest(snapshot)
        with self.unit() as db:
            existing = db.execute(
                "SELECT * FROM generations WHERE producer=? AND scope=? AND snapshot_id=?",
                (producer, scope, snapshot["snapshot_id"])).fetchone()
            if existing is not None:
                if existing["payload_hash"] != payload_hash:
                    raise ContractError("snapshot ID reused with different content")
                if existing["status"] != "staging":
                    return {"generation": existing["id"], "status": existing["status"],
                            "duplicate": True}
            latest = db.execute(
                "SELECT MAX(revision) FROM generations WHERE producer=? AND scope=?",
                (producer, scope)).fetchone()[0]
            if latest is not None and (revision < latest or (existing is None and revision == latest)):
                raise ContractError("out-of-order or conflicting inventory revision")
            if existing is None:
                state = "staging" if snapshot["complete"] else "incomplete"
                with _transaction(db):
                    generation = db.execute(
                        """INSERT INTO generations(producer,scope,snapshot_id,revision,observed_at,
                           payload_hash,expected_count,status) VALUES (?,?,?,?,?,?,?,?)""",
                        (producer, scope, snapshot["snapshot_id"], revision, snapshot["observed_at"],
                         payload_hash, len(snapshot["components"]), state)).lastrowid
                if state == "incomplete":
                    return {"generation": generation, "status": state, "duplicate": False}
            else:
                generation = existing["id"]
        # Staged rows are invisible to correlation until activation. The lock is
        # released after every batch so urgent work can proceed in between.
        items = snapshot["components"]
        for start in range(0, len(items), BATCH_SIZE):
            batch = [(generation, c["asset_id"], c["component_id"], c["ecosystem"],
                      c.get("source_package", c["name"]), canonical(c))
                     for c in items[start:start + BATCH_SIZE]]
            with self.unit() as db, _transaction(db):
                db.executemany(
                    """INSERT INTO observations(generation_id,asset_id,component_id,ecosystem,package,payload)
                       VALUES (?,?,?,?,?,?) ON CONFLICT(generation_id,asset_id,component_id) DO NOTHING""",
                    batch)
        with self.unit() as db, _transaction(db):
            status = db.execute("SELECT status FROM generations WHERE id=?",
                                (generation,)).fetchone()["status"]
            if status == "active":  # an identical concurrent ingestion activated it
                return {"generation": generation, "status": status, "duplicate": True}
            if status != "staging":
                raise ContractError(f"generation is {status}, not staging")
            count = db.execute("SELECT COUNT(*) FROM observations WHERE generation_id=?",
                               (generation,)).fetchone()[0]
            if count != len(items):
                raise RuntimeError("staged snapshot count mismatch")
            active = db.execute(
                """SELECT g.revision FROM active_generations a JOIN generations g
                   ON g.id=a.generation_id WHERE a.producer=? AND a.scope=?""",
                (producer, scope)).fetchone()
            if active is not None and active["revision"] >= revision:
                raise ContractError("a newer inventory revision was activated during staging")
            db.execute(
                """UPDATE generations SET status='retired' WHERE id=(
                   SELECT generation_id FROM active_generations WHERE producer=? AND scope=?)""",
                (producer, scope))
            db.execute("UPDATE generations SET status='active' WHERE id=?", (generation,))
            db.execute(
                """INSERT INTO active_generations VALUES (?,?,?) ON CONFLICT(producer,scope)
                   DO UPDATE SET generation_id=excluded.generation_id""", (producer, scope, generation))
            epoch = self._enqueue(db)
        return {"generation": generation, "status": "active", "epoch": epoch}

    # -- intelligence ------------------------------------------------------

    def ingest_advisory(self, advisory):
        key = (advisory["source"], advisory["advisory_id"])
        payload_hash = digest(advisory)
        with self.unit() as db, _transaction(db):
            old = db.execute(
                "SELECT r.* FROM advisory_heads h JOIN advisory_revisions r ON r.id=h.revision_id "
                "WHERE h.source=? AND h.advisory_id=?", key).fetchone()
            if old is not None:
                if old["vulnerability_id"] != advisory["vulnerability_id"]:
                    raise ContractError("changing vulnerability identity requires explicit reconciliation")
                if advisory["revision"] < old["revision"]:
                    raise ContractError("out-of-order advisory revision")
                if advisory["revision"] == old["revision"]:
                    if payload_hash != old["payload_hash"]:
                        raise ContractError("advisory revision reused with different content")
                    return {"advisory_revision": old["id"], "duplicate": True}
            row_id = db.execute(
                """INSERT INTO advisory_revisions(source,advisory_id,vulnerability_id,revision,
                   ecosystem,package,payload_hash,payload) VALUES (?,?,?,?,?,?,?,?)""",
                (*key, advisory["vulnerability_id"], advisory["revision"], advisory["ecosystem"],
                 advisory["package"], payload_hash, canonical(advisory))).lastrowid
            db.execute(
                """INSERT INTO advisory_heads VALUES (?,?,?) ON CONFLICT(source,advisory_id)
                   DO UPDATE SET revision_id=excluded.revision_id""", (*key, row_id))
            epoch = self._enqueue(db)
        return {"advisory_revision": row_id, "epoch": epoch}

    # -- correlation -------------------------------------------------------

    def next_batch(self, limit):
        """Read one bounded batch; returns (token, candidates) or None when idle.

        The token pins the epoch and job cursor; commit_batch rejects it if either
        moved, so concurrent or stale workers cannot commit the same batch twice.
        """
        with self.unit() as db:
            epoch = self._epoch(db)
            # Full reconciliation is intentional in this offline slice. New inputs supersede
            # unfinished scans; old decisions remain visible with their original epoch.
            with _transaction(db):
                db.execute("UPDATE jobs SET status='superseded' WHERE epoch<? AND status='pending'",
                           (epoch,))
            job = db.execute("SELECT * FROM jobs WHERE epoch=? AND status='pending'",
                             (epoch,)).fetchone()
            if job is None:
                return None
            cursor = (job["observation_cursor"], job["vulnerability_cursor"])
            rows = db.execute(
                """SELECT DISTINCT o.id AS observation_id, r.vulnerability_id
                   FROM observations o JOIN active_generations g ON o.generation_id=g.generation_id
                   JOIN advisory_revisions r ON r.ecosystem=o.ecosystem AND r.package=o.package
                   JOIN advisory_heads h ON h.revision_id=r.id
                   WHERE (o.id,r.vulnerability_id)>(?,?)
                   ORDER BY o.id,r.vulnerability_id LIMIT ?""", (*cursor, limit)).fetchall()
            results = []
            for row in rows:
                obs = db.execute(
                    """SELECT o.*,g.producer,g.scope FROM observations o JOIN generations g
                       ON g.id=o.generation_id WHERE o.id=?""", (row["observation_id"],)).fetchone()
                evidence = db.execute(
                    """SELECT r.id,r.payload FROM advisory_revisions r JOIN advisory_heads h
                       ON h.revision_id=r.id
                       WHERE r.ecosystem=? AND r.package=? AND r.vulnerability_id=? ORDER BY r.id""",
                    (obs["ecosystem"], obs["package"], row["vulnerability_id"])).fetchall()
                results.append({"observation_id": obs["id"], "producer": obs["producer"],
                                "scope": obs["scope"], "asset_id": obs["asset_id"],
                                "component_id": obs["component_id"],
                                "vulnerability_id": row["vulnerability_id"],
                                "component": json.loads(obs["payload"]),
                                "advisories": [json.loads(e["payload"]) for e in evidence],
                                "evidence_ids": [e["id"] for e in evidence]})
        return (epoch, *cursor), results

    def commit_batch(self, token, results):
        epoch, *cursor = token
        with self.unit() as db, _transaction(db):
            if epoch != self._epoch(db):
                raise StaleBatch("inputs changed since the batch was read")
            job = db.execute("SELECT * FROM jobs WHERE epoch=?", (epoch,)).fetchone()
            if job is None or job["status"] != "pending" or \
                    [job["observation_cursor"], job["vulnerability_cursor"]] != cursor:
                raise StaleBatch("job progressed since the batch was read")
            if not results:
                db.execute("UPDATE jobs SET status='done' WHERE epoch=?", (epoch,))
                return
            for item in results:
                key = tuple(item[k] for k in
                            ("producer", "scope", "asset_id", "component_id", "vulnerability_id"))
                old = db.execute(
                    """SELECT * FROM findings WHERE producer=? AND scope=? AND asset_id=?
                       AND component_id=? AND vulnerability_id=?""", key).fetchone()
                applicability, priority = item["applicability"], item["priority"]
                db.execute(
                    """INSERT INTO findings(producer,scope,asset_id,component_id,vulnerability_id,
                       applicability,priority,epoch) VALUES (?,?,?,?,?,?,?,?)
                       ON CONFLICT(producer,scope,asset_id,component_id,vulnerability_id)
                       DO UPDATE SET applicability=excluded.applicability,
                       priority=excluded.priority,epoch=excluded.epoch""",
                    (*key, applicability, priority, epoch))
                finding_id = db.execute(
                    """SELECT id FROM findings WHERE producer=? AND scope=? AND asset_id=?
                       AND component_id=? AND vulnerability_id=?""", key).fetchone()[0]
                db.execute(
                    """INSERT INTO decisions(finding_id,epoch,observation_id,applicability,priority,
                       reason,evidence,policy_version) VALUES (?,?,?,?,?,?,?,?)""",
                    (finding_id, epoch, item["observation_id"], applicability, priority,
                     item["reason"], canonical(item["evidence_ids"]), item["policy_version"]))
                if old is None or (old["applicability"], old["priority"]) != (applicability, priority):
                    db.execute(
                        "INSERT INTO outbox(finding_id,epoch,event_type,payload) VALUES (?,?,?,?)",
                        (finding_id, epoch, "finding.assessed",
                         canonical({"applicability": applicability, "priority": priority,
                                    "reason": item["reason"],
                                    "vulnerability_id": item["vulnerability_id"]})))
            last = results[-1]
            db.execute("UPDATE jobs SET observation_cursor=?,vulnerability_cursor=? WHERE epoch=?",
                       (last["observation_id"], last["vulnerability_id"], epoch))

    # -- reads (interim: step 4 replaces these with exported snapshots) -----

    def status(self):
        with self.unit() as db:
            return {"epoch": self._epoch(db),
                    "schema_version": db.execute("PRAGMA user_version").fetchone()[0],
                    "generations": [dict(r) for r in db.execute(
                        """SELECT producer,scope,snapshot_id,revision,observed_at,status,expected_count
                           FROM generations WHERE status!='retired' ORDER BY id LIMIT 100""")],
                    "pending_jobs": db.execute(
                        "SELECT COUNT(*) FROM jobs WHERE status='pending'").fetchone()[0],
                    "outbox_events": db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0],
                    "sqlite_version": sqlite3.sqlite_version,
                    "mode": "offline prototype; no delivery or live monitoring"}

    def findings(self, after, limit):
        with self.unit() as db:
            return [dict(r) for r in db.execute(
                """SELECT f.*,d.reason,d.evidence,d.policy_version,
                          CASE WHEN f.epoch=? THEN 0 ELSE 1 END AS stale
                   FROM findings f JOIN decisions d ON d.finding_id=f.id AND d.epoch=f.epoch
                   WHERE f.id>? ORDER BY f.id LIMIT ?""", (self._epoch(db), after, limit))]

    def events(self, after, limit):
        with self.unit() as db:
            return [dict(r) for r in db.execute(
                "SELECT * FROM outbox WHERE id>? ORDER BY id LIMIT ?", (after, limit))]
