import copy
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from vulnmon.common.contracts import ContractError
from vulnmon.correlatord.persistence.sqlite import LockTimeout, StaleBatch, Store
from vulnmon.correlatord.service import Core
from vulnmon.correlatord.matchers import Applicability, evaluate

FIXTURES = Path(__file__).parent / "fixtures"


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "state.db"
        self.inventory = json.loads((FIXTURES / "inventory.json").read_text())
        self.advisory = json.loads((FIXTURES / "advisory.json").read_text())

    def store(self, **kw):
        store = Store(self.path, **kw)
        store.migrate()
        return store

    def seed(self, core):
        core.ingest_inventory(self.inventory)
        core.ingest_advisory(self.advisory)

    def snapshot(self, revision, version=None):
        snapshot = copy.deepcopy(self.inventory)
        snapshot.update(snapshot_id=f"snapshot-{revision}", revision=revision)
        if version is not None:
            snapshot["components"][0]["version"] = version
        return snapshot

    def test_atomic_activation_and_idempotency(self):
        store = self.store()
        core = Core(store)
        first = core.ingest_inventory(self.inventory)
        self.assertTrue(core.ingest_inventory(self.inventory)["duplicate"])
        partial = dict(self.snapshot(2), complete=False, components=[])
        self.assertEqual(core.ingest_inventory(partial)["status"], "incomplete")
        self.assertEqual(store.epoch(), first["epoch"])
        active = [g for g in store.status()["generations"] if g["status"] == "active"]
        self.assertEqual(active[0]["snapshot_id"], "snapshot-1")
        with self.assertRaises(ContractError):
            core.ingest_inventory(dict(self.inventory, components=[]))

    def test_interrupted_staging_resume(self):
        store = self.store()
        core = Core(store)
        core.ingest_inventory(self.inventory)
        next_snapshot = self.snapshot(2, "1:1.0-1ubuntu2")
        original = store._enqueue
        def fail(db):
            raise RuntimeError("injected activation failure")
        store._enqueue = fail
        with self.assertRaises(RuntimeError):
            core.ingest_inventory(next_snapshot)
        store._enqueue = original
        active = [g for g in store.status()["generations"] if g["status"] == "active"]
        self.assertEqual(active[0]["snapshot_id"], "snapshot-1")
        self.assertEqual(Core(self.store()).ingest_inventory(next_snapshot)["status"], "active")

    def test_revisions_and_writer_exclusion(self):
        store = self.store()
        core = Core(store)
        self.seed(core)
        self.assertTrue(core.ingest_advisory(self.advisory)["duplicate"])
        with self.assertRaises(ContractError):
            core.ingest_advisory(dict(self.advisory, impact="different"))
        with store.unit():
            with self.assertRaises(LockTimeout):
                Store(self.path, lock_timeout=0.1).status()
        store.status()  # lock released after the unit

    def test_unknown_origin(self):
        component = dict(self.inventory["components"][0], origin="custom")
        self.assertEqual(evaluate(component, self.advisory).applicability, Applicability.UNKNOWN)

    @unittest.skipUnless(shutil.which("dpkg"), "Ubuntu dpkg required")
    def test_affected_fixed_and_rollback(self):
        store = self.store()
        core = Core(store)
        self.seed(core)
        core.correlate(max_batches=10)
        finding = store.findings(0, 10)[0]
        self.assertEqual((finding["applicability"], finding["priority"]), ("affected", "P0"))
        self.assertEqual(len(store.events(0, 10)), 1)
        core.correlate(max_batches=10)
        self.assertEqual(len(store.events(0, 10)), 1)
        for revision, version, expected in [
            (2, "1:1.0-1ubuntu2", "fixed"), (3, "1:1.0-1ubuntu1", "affected")
        ]:
            core.ingest_inventory(self.snapshot(revision, version))
            self.assertEqual(store.findings(0, 10)[0]["stale"], 1)
            core.correlate(max_batches=10)
            current = store.findings(0, 10)[0]
            self.assertEqual(current["id"], finding["id"])
            self.assertEqual(current["applicability"], expected)
            self.assertEqual(current["stale"], 0)
        self.assertEqual(len(store.events(0, 10)), 3)

    @unittest.skipUnless(shutil.which("dpkg"), "Ubuntu dpkg required")
    def test_durable_job_and_atomic_outbox(self):
        store = self.store()
        self.seed(Core(store))
        # Force an exception after finding/decision insertion and before event commit.
        with store.unit() as db:
            db.execute("""CREATE TRIGGER fail_outbox BEFORE INSERT ON outbox
                          BEGIN SELECT RAISE(ABORT,'injected failure'); END""")
        with self.assertRaises(sqlite3.IntegrityError):
            Core(store).correlate()
        self.assertEqual(store.findings(0, 10), [])
        self.assertEqual(store.events(0, 10), [])
        with store.unit() as db:
            db.execute("DROP TRIGGER fail_outbox")
        Core(self.store()).correlate(max_batches=10)
        self.assertEqual(len(store.events(0, 10)), 1)

    @unittest.skipUnless(shutil.which("dpkg"), "Ubuntu dpkg required")
    def test_conflicting_evidence(self):
        store = self.store()
        core = Core(store)
        self.seed(core)
        core.ingest_advisory(dict(self.advisory, advisory_id="other",
                                  status="not_affected", fixed_version=None))
        core.correlate(max_batches=10)
        self.assertEqual(store.findings(0, 10)[0]["applicability"], "unknown")

    def test_stale_result_rejected(self):
        store = self.store()
        core = Core(store)
        self.seed(core)
        token, candidates = store.next_batch(10)
        core.ingest_advisory(dict(self.advisory, revision=2))
        with self.assertRaises(StaleBatch):
            store.commit_batch(token, candidates)


if __name__ == "__main__":
    unittest.main()
