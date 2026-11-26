import errno
import os
from pathlib import Path
import tempfile
import unittest

from vulnmon.common import receipts
from vulnmon.common.contracts import ContractError, canonical, loads
from vulnmon.common.spool import (
    InvalidMessage, Quota, Spool, SpoolConflict, SpoolError, SpoolFull, make_manifest,
)


class Crash(Exception):
    pass


def crash_at(point, exc=None):
    def hook(name):
        if name == point:
            raise exc or Crash(point)
    return hook


def manifest(message_id="msg-1", payload=None, created_at="2026-11-26T08:00:00Z", **kw):
    return make_manifest(kw.get("kind", "inventory.snapshot"), kw.get("producer", "fixture"),
                         message_id, payload if payload is not None else {"value": 1}, created_at)


class SpoolTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "spool"
        self.spool = Spool(self.root)
        self.spool.ensure()

    def ls(self, sub):
        return sorted(os.listdir(self.root / sub))

    def faulty(self, point, exc=None, **kw):
        return Spool(self.root, fault=crash_at(point, exc), **kw)

    def raw_entry(self, name, data):
        (self.root / "new" / name).write_bytes(data)

    def test_roundtrip_and_archive(self):
        published = self.spool.publish(manifest())
        self.assertFalse(published.duplicate)
        self.assertEqual(self.ls("tmp"), [])
        entries = self.spool.scan()
        self.assertEqual([e.name for e in entries], ["msg-1.json"])
        message = self.spool.read(entries[0], kinds={"inventory.snapshot"}, producers={"fixture"})
        self.assertEqual(message.payload, {"value": 1})
        self.assertTrue(self.spool.acknowledge(message))
        self.assertEqual(self.ls("new"), [])
        self.assertEqual(len(self.ls("done")), 1)
        self.assertFalse(self.spool.acknowledge(message))

    def test_identical_retry_is_idempotent_conflict_never_overwrites(self):
        self.spool.publish(manifest())
        retry = self.spool.publish(manifest(created_at="2026-11-26T09:00:00Z"))
        self.assertTrue(retry.duplicate)
        with self.assertRaises(SpoolConflict):
            self.spool.publish(manifest(payload={"value": 2}))
        with self.assertRaises(SpoolConflict):
            self.spool.publish(manifest(kind="advisory.normalized"))
        self.assertEqual(self.spool.read("msg-1.json").payload, {"value": 1})

    def test_crash_before_link_publishes_nothing(self):
        for point in ("publish.tmp_created", "publish.tmp_written", "publish.tmp_synced"):
            with self.subTest(point=point), self.assertRaises(Crash):
                self.faulty(point).publish(manifest())
            self.assertEqual(self.ls("new"), [])
            self.assertEqual(self.ls("tmp"), [])
        self.assertFalse(self.spool.publish(manifest()).duplicate)

    def test_disk_full_is_explicit_failure(self):
        with self.assertRaises(OSError) as ctx:
            self.faulty("publish.tmp_written", OSError(errno.ENOSPC, "No space")).publish(manifest())
        self.assertEqual(ctx.exception.errno, errno.ENOSPC)
        self.assertEqual((self.ls("new"), self.ls("tmp")), ([], []))

    def test_crash_after_link_retry_completes(self):
        for i, point in enumerate(("publish.linked", "publish.dir_synced")):
            m = manifest(f"msg-{i}")
            with self.subTest(point=point):
                with self.assertRaises(Crash):
                    self.faulty(point).publish(m)
                self.assertEqual(self.ls("tmp"), [])
                self.assertTrue(self.spool.publish(m).duplicate)
                self.assertEqual(self.spool.read(f"msg-{i}.json").content_sha256,
                                 m["content_sha256"])

    def test_interrupted_acknowledgement_is_replayable(self):
        for i, point in enumerate(("ack.linked", "ack.archived", "ack.unlinked")):
            with self.subTest(point=point):
                self.spool.publish(manifest(f"ack-{i}"))
                message = self.spool.read(f"ack-{i}.json")
                with self.assertRaises(Crash):
                    self.faulty(point).acknowledge(message)
                if point == "ack.unlinked":
                    self.assertFalse(self.spool.acknowledge(message))
                else:
                    again = self.spool.read(f"ack-{i}.json")
                    self.assertEqual(again.content_sha256, message.content_sha256)
                    self.assertTrue(self.spool.acknowledge(again))
                self.assertNotIn(f"ack-{i}.json", self.ls("new"))
        self.assertEqual(len(self.ls("done")), 3)

    def test_replaced_entry_is_not_acknowledged(self):
        self.spool.publish(manifest())
        message = self.spool.read("msg-1.json")
        path = self.root / "new" / "msg-1.json"
        path.unlink()  # the replacement may reuse the inode number
        path.write_bytes(canonical(manifest(payload={"value": 2})).encode())
        with self.assertRaises(SpoolConflict):
            self.spool.acknowledge(message)
        self.assertEqual(self.ls("new"), ["msg-1.json"])
        self.assertEqual(self.ls("done"), [])

    def test_hostile_entries_rejected_and_quarantined(self):
        good = manifest("good")
        bad_hash = dict(good, message_id="bad-hash", content_sha256="0" * 64)
        cases = {
            "not-json.json": b"{",
            "dupkey.json": b'{"a":1,"a":2}',
            "nan.json": b'{"a":NaN}',
            "deep.json": b"[" * 100000 + b"]" * 100000,
            "bad-hash.json": canonical(bad_hash).encode(),
            "renamed.json": canonical(good).encode(),
            "oversize.json": b" " * 2048,
            "bad name.json": canonical(good).encode(),
            "no-suffix": canonical(good).encode(),
        }
        for name, data in cases.items():
            self.raw_entry(name, data)
        os.symlink("/etc/passwd", self.root / "new" / "link.json")
        os.mkdir(self.root / "new" / "dir.json")
        hardlinked = self.root / "elsewhere"
        hardlinked.write_bytes(canonical(manifest("hard")).encode())
        os.link(hardlinked, self.root / "new" / "hard.json")
        os.link(hardlinked, self.root / "hardcopy")
        spool = Spool(self.root, max_message_bytes=1024, max_quarantine=100)
        entries = spool.scan(limit=100)
        self.assertEqual(len(entries), len(cases) + 3)
        for entry in entries:
            with self.subTest(entry=entry.name):
                with self.assertRaises(InvalidMessage):
                    spool.read(entry)
                self.assertIsNotNone(spool.quarantine(entry, "test rejection"))
        self.assertEqual(self.ls("new"), [])
        self.assertEqual(spool.stats().quarantined, len(entries))
        self.assertTrue(os.path.exists("/etc/passwd"))

    def test_kind_producer_and_owner_checks(self):
        self.spool.publish(manifest())
        for kw in ({"kinds": {"advisory.normalized"}}, {"producers": {"other"}}):
            with self.subTest(**{k: sorted(v) for k, v in kw.items()}), \
                    self.assertRaises(InvalidMessage):
                self.spool.read("msg-1.json", **kw)
        with self.assertRaises(InvalidMessage):
            Spool(self.root, expected_uids={os.getuid() + 1}).read("msg-1.json")
        Spool(self.root, expected_uids={os.getuid()}).read("msg-1.json")

    def test_quarantine_bounded(self):
        for i in range(3):
            self.raw_entry(f"p{i}.json", b"{")
        spool = Spool(self.root, max_quarantine=2)
        spool.quarantine("p0.json", "x")
        spool.quarantine("p1.json", "x")
        with self.assertRaises(SpoolFull):
            spool.quarantine("p2.json", "x")
        self.assertEqual(self.ls("new"), ["p2.json"])

    def test_unsafe_directories_rejected(self):
        new = self.root / "new"
        os.rename(new, self.root / "real-new")
        os.symlink(self.root / "real-new", new)
        with self.assertRaises(SpoolError):
            self.spool.publish(manifest())
        os.unlink(new)
        os.rename(self.root / "real-new", new)
        os.chmod(new, 0o777)
        try:
            with self.assertRaises(SpoolError):
                self.spool.scan()
        finally:
            os.chmod(new, 0o750)

    def test_quota_reserves_urgent_capacity(self):
        size = len(canonical(manifest("q-0")).encode()) + 1
        spool = Spool(self.root, quota=Quota(max_files=3, max_bytes=100 * size, reserved_files=1))
        spool.publish(manifest("q-0"))
        spool.publish(manifest("q-1"))
        with self.assertRaises(SpoolFull):
            spool.publish(manifest("q-2"))
        spool.publish(manifest("q-2"), urgent=True)
        with self.assertRaises(SpoolFull):
            spool.publish(manifest("q-3"), urgent=True)
        self.assertTrue(spool.publish(manifest("q-0")).duplicate)
        with self.assertRaises(SpoolFull):
            Spool(self.root, quota=Quota(10, 10 ** 12, min_free_bytes=2 ** 62)).publish(
                manifest("q-4"), urgent=True)

    def test_cleanup_and_stats(self):
        with self.assertRaises(Crash):
            Spool(self.root, fault=crash_at("publish.tmp_synced")).publish(manifest())
        stale = self.root / "tmp" / ".abandoned.1.ab.tmp"
        stale.write_bytes(b"partial")
        os.utime(stale, (1, 1))
        (self.root / "tmp" / "keep").write_bytes(b"")
        self.assertEqual(self.spool.cleanup_tmp(60), 1)
        self.assertEqual(self.ls("tmp"), ["keep"])
        self.assertIsNone(self.spool.stats().oldest_age_seconds)
        self.spool.publish(manifest())
        stats = self.spool.stats()
        self.assertEqual((stats.files, stats.quarantined), (1, 0))
        self.assertGreaterEqual(stats.oldest_age_seconds, 0)
        message = self.spool.read("msg-1.json")
        self.spool.acknowledge(message)
        os.utime(self.root / "done" / os.listdir(self.root / "done")[0], (1, 1))
        self.assertEqual(self.spool.prune_done(60), 1)

    def test_published_file_mode_and_bytes(self):
        Spool(self.root, file_mode=0o600).publish(manifest())
        path = self.root / "new" / "msg-1.json"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(loads(path.read_bytes()), manifest())


class ManifestAndReceiptTests(unittest.TestCase):
    def test_manifest_validation(self):
        for kw in ({"message_id": "../etc"}, {"message_id": ".hidden"},
                   {"kind": "Inventory"}, {"producer": ""}, {"created_at": "2026-11-26T08:00:00"}):
            with self.subTest(**kw), self.assertRaises(ContractError):
                make_manifest(kw.get("kind", "a.b"), kw.get("producer", "p"),
                              kw.get("message_id", "m"), {}, kw.get("created_at"))
        with self.assertRaises(ContractError):
            make_manifest("a.b", "p", "m", [])

    def test_strict_loader_bounds(self):
        for raw in (b"[" * 200000 + b"]" * 200000, b'{"a":1,"a":2}', b"\xff", b"1e999x"):
            with self.subTest(raw=raw[:8]), self.assertRaises(ContractError):
                loads(raw)
        with self.assertRaises(ContractError):
            loads(b"[1]", limit=2)

    def test_receipt_validation(self):
        good = {"event_id": "e1", "attempt_id": "a1", "channel": "pager", "outcome": "delivered",
                "occurred_at": "2026-11-26T08:00:00Z", "provider_reference": None, "detail": None}
        self.assertIs(receipts.validate(good), good)
        for change in ({"outcome": "read"}, {"detail": "x" * 2000}, {"event_id": ""},
                       {"extra": 1}, {"occurred_at": "yesterday"}):
            with self.subTest(change=change), self.assertRaises(ContractError):
                receipts.validate(dict(good, **change))


if __name__ == "__main__":
    unittest.main()
