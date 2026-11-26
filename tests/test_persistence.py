import copy
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
import unittest
from unittest import mock

from vulnmon.common.contracts import ContractError
from vulnmon.correlatord.persistence import sqlite as persistence
from vulnmon.correlatord.persistence.sqlite import (
    LockTimeout, SchemaMismatch, StaleBatch, Store, load_migrations,
)
from vulnmon.correlatord.service import Core

FIXTURES = Path(__file__).parent / "fixtures"
REAL_MIGRATIONS = Path(persistence.__file__).parent / "migrations"


class MigrationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / "state.db"
        self.migrations = self.dir / "migrations"
        self.migrations.mkdir()
        shutil.copy(REAL_MIGRATIONS / "0001_initial.sql", self.migrations)

    def user_version(self):
        with sqlite3.connect(self.path) as db:
            return db.execute("PRAGMA user_version").fetchone()[0]

    def test_operations_require_explicit_migration(self):
        store = Store(self.path)
        with self.assertRaises(SchemaMismatch):
            store.status()
        self.assertEqual(store.migrate(), {"from": 0, "to": 1})
        self.assertEqual(store.migrate(), {"from": 1, "to": 1})
        self.assertEqual(store.status()["schema_version"], 1)

    def test_newer_database_refused(self):
        Store(self.path).migrate()
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA user_version = 99")
        with self.assertRaises(SchemaMismatch):
            Store(self.path).migrate()

    def test_sequential_upgrade_and_atomic_failure(self):
        Store(self.path, migrations=self.migrations).migrate()
        (self.migrations / "0002_extra.sql").write_text("CREATE TABLE extra (id INTEGER PRIMARY KEY);")
        (self.migrations / "0003_broken.sql").write_text(
            "CREATE TABLE partial (id INTEGER);\nINSERT INTO missing VALUES (1);")
        with self.assertRaises(sqlite3.OperationalError):
            Store(self.path, migrations=self.migrations).migrate()
        self.assertEqual(self.user_version(), 2)
        with sqlite3.connect(self.path) as db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("extra", tables)
        self.assertNotIn("partial", tables)
        (self.migrations / "0003_broken.sql").write_text("CREATE TABLE fixed (id INTEGER);")
        self.assertEqual(Store(self.path, migrations=self.migrations).migrate(),
                         {"from": 2, "to": 3})

    def test_migration_set_validation(self):
        (self.migrations / "0003_gap.sql").write_text("SELECT 1;")
        with self.assertRaises(SchemaMismatch):
            load_migrations(self.migrations)
        (self.migrations / "0003_gap.sql").unlink()
        (self.migrations / "0002_tx.sql").write_text("BEGIN;\nSELECT 1;\nCOMMIT;")
        with self.assertRaises(SchemaMismatch):
            load_migrations(self.migrations)

    def test_packaged_migrations_load(self):
        self.assertEqual([v for v, _, _ in load_migrations()], [1])


class BatchLockTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "state.db"
        self.store = Store(self.path)
        self.store.migrate()
        self.inventory = json.loads((FIXTURES / "inventory.json").read_text())
        self.advisory = json.loads((FIXTURES / "advisory.json").read_text())
        component = self.inventory["components"][0]
        self.inventory["components"] = [
            dict(component, component_id=f"c{i}") for i in range(3)]
        patcher = mock.patch.object(persistence, "BATCH_SIZE", 1)
        patcher.start()
        self.addCleanup(patcher.stop)

    def other(self):
        return Core(Store(self.path, lock_timeout=0.1))

    def snapshot(self, revision):
        snapshot = copy.deepcopy(self.inventory)
        snapshot.update(snapshot_id=f"snapshot-{revision}", revision=revision)
        return snapshot

    def test_lock_released_between_staging_batches(self):
        interleaved = []

        def hook():
            if len(interleaved) == 1:  # after the first staging batch
                interleaved.append(self.other().ingest_advisory(self.advisory))
            else:
                interleaved.append(None)
        self.store.after_unit = hook
        result = Core(self.store).ingest_inventory(self.inventory)
        self.store.after_unit = None
        self.assertEqual(interleaved[1]["epoch"], 1)
        self.assertEqual(result, {"generation": 1, "status": "active", "epoch": 2})
        # generation insert, 3 staging batches, activation
        self.assertEqual(len(interleaved), 5)

    def test_newer_revision_during_staging_blocks_activation(self):
        Core(self.store).ingest_inventory(self.snapshot(1))
        calls = []

        def hook():
            calls.append(1)
            if len(calls) == 2:
                self.other().ingest_inventory(self.snapshot(3))
        self.store.after_unit = hook
        with self.assertRaises(ContractError):
            Core(self.store).ingest_inventory(self.snapshot(2))
        self.store.after_unit = None
        active = [g for g in self.store.status()["generations"] if g["status"] == "active"]
        self.assertEqual([g["revision"] for g in active], [3])

    def test_concurrent_batch_commits_once(self):
        core = Core(self.store)
        core.ingest_inventory(self.inventory)
        core.ingest_advisory(self.advisory)
        first = self.store.next_batch(2)
        second = self.store.next_batch(2)
        self.assertEqual(first[0], second[0])
        for _, items in (first, second):
            for item in items:
                item.update(applicability="unknown", reason="test", priority=None,
                            policy_version="test")
        self.store.commit_batch(*first)
        with self.assertRaises(StaleBatch):
            self.store.commit_batch(*second)
        with self.store.unit() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0], 2)

    def test_correlate_discards_stale_batch_and_continues(self):
        core = Core(self.store)
        core.ingest_inventory(self.inventory)
        core.ingest_advisory(self.advisory)
        real = self.store.commit_batch
        calls = []

        def flaky(token, results):
            calls.append(token)
            if len(calls) == 1:
                raise StaleBatch("injected")
            return real(token, results)
        self.store.commit_batch = flaky
        result = core.correlate(batch_size=2, max_batches=10)
        self.assertEqual(result["stale_batches"], 1)
        self.assertEqual(result["evaluated"], 3)
        self.assertEqual(result["status"]["pending_jobs"], 0)

    def test_lock_wait_is_bounded(self):
        with self.store.unit():
            start = time.monotonic()
            with self.assertRaises(LockTimeout):
                Store(self.path, lock_timeout=0.2).status()
            self.assertLess(time.monotonic() - start, 2)


if __name__ == "__main__":
    unittest.main()
