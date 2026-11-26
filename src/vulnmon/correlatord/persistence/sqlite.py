"""Single-node offline persistence. The CLI holds an exclusive writer lease."""
from contextlib import contextmanager
from importlib.resources import files
import fcntl
import json
from pathlib import Path
import sqlite3

from vulnmon.common.contracts import ContractError, canonical, digest

BATCH_SIZE = 500


class Store:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.lock = None
        self.db = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = open(str(self.path) + ".writer.lock", "a", encoding="utf-8")
        try:
            # Never unlink a flock file: concurrent processes could lock different inodes.
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(self.path, isolation_level=None, timeout=5)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA busy_timeout=5000")
            if self.db.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                raise RuntimeError("WAL unavailable")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                schema = files(__package__).joinpath("schema.sql").read_text(encoding="utf-8")
                self.db.executescript(schema)
            elif version != 1:
                raise RuntimeError(f"unsupported database schema version {version}")
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *exc):
        try:
            if self.db is not None:
                self.db.close()
        finally:
            if self.lock is not None:
                self.lock.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def epoch(self):
        return self.db.execute("SELECT value FROM metadata WHERE key='epoch'").fetchone()[0]

    def _enqueue(self):
        epoch = self.epoch() + 1
        self.db.execute("UPDATE metadata SET value=? WHERE key='epoch'", (epoch,))
        self.db.execute("INSERT INTO jobs(epoch,status) VALUES (?,'pending')", (epoch,))
        return epoch

    def ingest_inventory(self, snapshot):
        producer, scope = snapshot["producer"], snapshot["scope"]
        revision = snapshot["revision"]
        payload_hash = digest(snapshot)
        existing = self.db.execute(
            "SELECT * FROM generations WHERE producer=? AND scope=? AND snapshot_id=?",
            (producer, scope, snapshot["snapshot_id"])).fetchone()
        if existing is not None:
            if existing["payload_hash"] != payload_hash:
                raise ContractError("snapshot ID reused with different content")
            if existing["status"] != "staging":
                return {"generation": existing["id"], "status": existing["status"], "duplicate": True}
        latest = self.db.execute(
            "SELECT MAX(revision) FROM generations WHERE producer=? AND scope=?",
            (producer, scope)).fetchone()[0]
        if latest is not None and (revision < latest or (existing is None and revision == latest)):
            raise ContractError("out-of-order or conflicting inventory revision")
        if existing is None:
            state = "staging" if snapshot["complete"] else "incomplete"
            with self.transaction():
                generation = self.db.execute(
                    """INSERT INTO generations(producer,scope,snapshot_id,revision,observed_at,
                       payload_hash,expected_count,status) VALUES (?,?,?,?,?,?,?,?)""",
                    (producer, scope, snapshot["snapshot_id"], revision, snapshot["observed_at"],
                     payload_hash, len(snapshot["components"]), state)).lastrowid
            if state == "incomplete":
                return {"generation": generation, "status": state, "duplicate": False}
        else:
            generation = existing["id"]
        # Committed staging batches are invisible to the active generation query.
        items = snapshot["components"]
        for start in range(0, len(items), BATCH_SIZE):
            batch = [(generation, c["asset_id"], c["component_id"], c["ecosystem"],
                      c.get("source_package", c["name"]), canonical(c))
                     for c in items[start:start + BATCH_SIZE]]
            with self.transaction():
                self.db.executemany(
                    """INSERT INTO observations(generation_id,asset_id,component_id,ecosystem,package,payload)
                       VALUES (?,?,?,?,?,?) ON CONFLICT(generation_id,asset_id,component_id) DO NOTHING""",
                    batch)
        count = self.db.execute("SELECT COUNT(*) FROM observations WHERE generation_id=?",
                                (generation,)).fetchone()[0]
        if count != len(items):
            raise RuntimeError("staged snapshot count mismatch")
        with self.transaction():
            self.db.execute(
                """UPDATE generations SET status='retired' WHERE id=(
                   SELECT generation_id FROM active_generations WHERE producer=? AND scope=?)""",
                (producer, scope))
            self.db.execute("UPDATE generations SET status='active' WHERE id=?", (generation,))
            self.db.execute(
                """INSERT INTO active_generations VALUES (?,?,?) ON CONFLICT(producer,scope)
                   DO UPDATE SET generation_id=excluded.generation_id""", (producer, scope, generation))
            epoch = self._enqueue()
        return {"generation": generation, "status": "active", "epoch": epoch}

    def ingest_advisory(self, advisory):
        key = (advisory["source"], advisory["advisory_id"])
        payload_hash = digest(advisory)
        old = self.db.execute(
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
        with self.transaction():
            row_id = self.db.execute(
                """INSERT INTO advisory_revisions(source,advisory_id,vulnerability_id,revision,
                   ecosystem,package,payload_hash,payload) VALUES (?,?,?,?,?,?,?,?)""",
                (*key, advisory["vulnerability_id"], advisory["revision"], advisory["ecosystem"],
                 advisory["package"], payload_hash, canonical(advisory))).lastrowid
            self.db.execute(
                """INSERT INTO advisory_heads VALUES (?,?,?) ON CONFLICT(source,advisory_id)
                   DO UPDATE SET revision_id=excluded.revision_id""", (*key, row_id))
            epoch = self._enqueue()
        return {"advisory_revision": row_id, "epoch": epoch}

    def next_batch(self, limit):
        epoch = self.epoch()
        # Full reconciliation is intentional in this offline slice. New inputs supersede
        # unfinished scans; old decisions remain visible with their original epoch.
        with self.transaction():
            self.db.execute("UPDATE jobs SET status='superseded' WHERE epoch<? AND status='pending'", (epoch,))
        job = self.db.execute("SELECT * FROM jobs WHERE epoch=? AND status='pending'", (epoch,)).fetchone()
        if job is None:
            return None
        rows = self.db.execute(
            """SELECT DISTINCT o.id AS observation_id, r.vulnerability_id
               FROM observations o JOIN active_generations g ON o.generation_id=g.generation_id
               JOIN advisory_revisions r ON r.ecosystem=o.ecosystem AND r.package=o.package
               JOIN advisory_heads h ON h.revision_id=r.id
               WHERE (o.id,r.vulnerability_id)>(?,?)
               ORDER BY o.id,r.vulnerability_id LIMIT ?""",
            (job["observation_cursor"], job["vulnerability_cursor"], limit)).fetchall()
        results = []
        for row in rows:
            obs = self.db.execute(
                """SELECT o.*,g.producer,g.scope FROM observations o JOIN generations g
                   ON g.id=o.generation_id WHERE o.id=?""", (row["observation_id"],)).fetchone()
            evidence = self.db.execute(
                """SELECT r.id,r.payload FROM advisory_revisions r JOIN advisory_heads h ON h.revision_id=r.id
                   WHERE r.ecosystem=? AND r.package=? AND r.vulnerability_id=? ORDER BY r.id""",
                (obs["ecosystem"], obs["package"], row["vulnerability_id"])).fetchall()
            results.append({"observation_id": obs["id"], "producer": obs["producer"],
                            "scope": obs["scope"], "asset_id": obs["asset_id"],
                            "component_id": obs["component_id"], "vulnerability_id": row["vulnerability_id"],
                            "component": json.loads(obs["payload"]),
                            "advisories": [json.loads(e["payload"]) for e in evidence],
                            "evidence_ids": [e["id"] for e in evidence]})
        return epoch, results

    def commit_batch(self, epoch, results):
        with self.transaction():
            if epoch != self.epoch():
                raise RuntimeError("stale correlation result")
            if not results:
                self.db.execute("UPDATE jobs SET status='done' WHERE epoch=? AND status='pending'", (epoch,))
                return
            for item in results:
                key = tuple(item[k] for k in ("producer","scope","asset_id","component_id","vulnerability_id"))
                old = self.db.execute(
                    """SELECT * FROM findings WHERE producer=? AND scope=? AND asset_id=?
                       AND component_id=? AND vulnerability_id=?""", key).fetchone()
                applicability, priority = item["applicability"], item["priority"]
                self.db.execute(
                    """INSERT INTO findings(producer,scope,asset_id,component_id,vulnerability_id,
                       applicability,priority,epoch) VALUES (?,?,?,?,?,?,?,?)
                       ON CONFLICT(producer,scope,asset_id,component_id,vulnerability_id)
                       DO UPDATE SET applicability=excluded.applicability,
                       priority=excluded.priority,epoch=excluded.epoch""",
                    (*key, applicability, priority, epoch))
                finding_id = self.db.execute(
                    """SELECT id FROM findings WHERE producer=? AND scope=? AND asset_id=?
                       AND component_id=? AND vulnerability_id=?""", key).fetchone()[0]
                self.db.execute(
                    """INSERT INTO decisions(finding_id,epoch,observation_id,applicability,priority,
                       reason,evidence,policy_version) VALUES (?,?,?,?,?,?,?,?)""",
                    (finding_id, epoch, item["observation_id"], applicability, priority,
                     item["reason"], canonical(item["evidence_ids"]), item["policy_version"]))
                if old is None or (old["applicability"], old["priority"]) != (applicability, priority):
                    self.db.execute(
                        "INSERT INTO outbox(finding_id,epoch,event_type,payload) VALUES (?,?,?,?)",
                        (finding_id, epoch, "finding.assessed",
                         canonical({"applicability": applicability, "priority": priority,
                                    "reason": item["reason"], "vulnerability_id": item["vulnerability_id"]})))
            last = results[-1]
            self.db.execute(
                "UPDATE jobs SET observation_cursor=?,vulnerability_cursor=? WHERE epoch=?",
                (last["observation_id"], last["vulnerability_id"], epoch))

    def status(self):
        return {"epoch": self.epoch(),
                "generations": [dict(r) for r in self.db.execute(
                    """SELECT producer,scope,snapshot_id,revision,observed_at,status,expected_count
                       FROM generations WHERE status!='retired' ORDER BY id LIMIT 100""")],
                "pending_jobs": self.db.execute("SELECT COUNT(*) FROM jobs WHERE status='pending'").fetchone()[0],
                "outbox_events": self.db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0],
                "sqlite_version": sqlite3.sqlite_version,
                "mode": "offline prototype; no delivery or live monitoring"}

    def findings(self, after, limit):
        return [dict(r) for r in self.db.execute(
            """SELECT f.*,d.reason,d.evidence,d.policy_version,
                      CASE WHEN f.epoch=? THEN 0 ELSE 1 END AS stale
               FROM findings f JOIN decisions d ON d.finding_id=f.id AND d.epoch=f.epoch
               WHERE f.id>? ORDER BY f.id LIMIT ?""", (self.epoch(), after, limit))]

    def events(self, after, limit):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM outbox WHERE id>? ORDER BY id LIMIT ?", (after, limit))]
