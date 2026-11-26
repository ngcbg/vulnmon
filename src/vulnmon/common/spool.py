"""Durable filesystem spool: one producer direction, one consumer (protocol.md).

Layout (all on one filesystem)::

    <root>/tmp/          producer-private temporary files
    <root>/new/          published manifests awaiting consumption
    <root>/done/         acknowledged manifests (archive, pruned by retention)
    <root>/quarantine/   rejected entries with a reason record

Every operation works relative to directory file descriptors opened without
following symlinks, so a renamed or substituted path component cannot redirect
it. Publication is acknowledged only after the file and its directory entry are
synced. External delivery and consumption are at least once: consumers MUST
deduplicate by ``(message_id, content_sha256)`` in their own committed state.
"""
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import hashlib
import os
import re
import secrets
import stat
import time

from vulnmon.common.contracts import (
    ContractError, canonical, digest, fields, loads, string, timestamp,
)

SCHEMA_VERSION = 1
SUBDIRS = ("tmp", "new", "done", "quarantine")
DEFAULT_MAX_MESSAGE_BYTES = 64 * 1024 * 1024
MESSAGE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
KIND = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
SHA256 = re.compile(r"[0-9a-f]{64}")
SUFFIX = ".json"
REASON_SUFFIX = ".reason.json"

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class SpoolError(RuntimeError):
    """Operational failure; the operation was not acknowledged."""


class SpoolConflict(SpoolError):
    """A message ID is already bound to different content, or was replaced."""


class SpoolFull(SpoolError):
    """Quota, reserve or free-space limit reached; retry later or escalate."""


class InvalidMessage(ContractError):
    """The entry must not be processed; the consumer should quarantine it."""


@dataclass(frozen=True)
class Quota:
    """Advisory limits checked before publication (not atomic across producers).

    ``reserved_*`` capacity is usable only by ``publish(..., urgent=True)``. Whether
    work is urgent is the producer's trusted configuration, never a manifest field.
    """
    max_files: int
    max_bytes: int
    reserved_files: int = 0
    reserved_bytes: int = 0
    min_free_bytes: int = 0
    min_free_inodes: int = 0


@dataclass(frozen=True)
class Published:
    name: str
    message_id: str
    content_sha256: str
    duplicate: bool


@dataclass(frozen=True)
class Entry:
    name: str
    size: int
    mtime_ns: int
    regular: bool
    valid_name: bool


@dataclass(frozen=True)
class Message:
    name: str
    message_id: str
    kind: str
    producer: str
    created_at: str
    content_sha256: str
    payload: dict
    raw_sha256: str
    size: int
    published_ns: int
    device: int
    inode: int


@dataclass(frozen=True)
class Stats:
    files: int
    bytes: int
    oldest_age_seconds: float | None
    quarantined: int


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def make_manifest(kind, producer, message_id, payload, created_at=None):
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "message_id": message_id,
        "kind": kind,
        "producer": producer,
        "created_at": created_at or utc_now(),
        "content_sha256": digest(payload),
        "payload": payload,
    }
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest):
    fields(manifest, ("schema_version", "message_id", "kind", "producer",
                      "created_at", "content_sha256", "payload"))
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != SCHEMA_VERSION:
        raise ContractError("unsupported manifest schema version")
    for key, pattern in (("message_id", MESSAGE_ID), ("kind", KIND), ("content_sha256", SHA256)):
        if not isinstance(manifest[key], str) or not pattern.fullmatch(manifest[key]):
            raise ContractError(f"invalid {key}")
    if len(manifest["kind"]) > 64:
        raise ContractError("invalid kind")
    string(manifest["producer"], "producer")
    timestamp(manifest["created_at"])
    if not isinstance(manifest["payload"], dict):
        raise ContractError("payload must be an object")
    if digest(manifest["payload"]) != manifest["content_sha256"]:
        raise ContractError("content hash does not match payload")
    return manifest


def _same_message(left, right):
    keys = ("message_id", "kind", "producer", "content_sha256")
    return all(left[k] == right[k] for k in keys)


class Spool:
    def __init__(self, root, *, max_message_bytes=DEFAULT_MAX_MESSAGE_BYTES, quota=None,
                 file_mode=0o640, expected_uids=None, max_quarantine=1000, fault=None):
        self.root = os.fspath(root)
        self.max_message_bytes = max_message_bytes
        self.quota = quota
        self.file_mode = file_mode
        self.expected_uids = None if expected_uids is None else frozenset(expected_uids)
        self.max_quarantine = max_quarantine
        # Test hook: called with a named protocol point; raising simulates a crash there.
        self._fault = fault or (lambda point: None)

    # -- directories -------------------------------------------------------

    def ensure(self, mode=0o750):
        """Create the layout (development/tests; deployment sets real ownership)."""
        os.makedirs(self.root, mode=mode, exist_ok=True)
        with ExitStack() as stack:
            root = self._open_root(stack)
            for name in SUBDIRS:
                try:
                    os.mkdir(name, mode, dir_fd=root)
                except FileExistsError:
                    pass
            for name in SUBDIRS:
                self._open_dir(stack, root, name)
            os.fsync(root)

    def _open_root(self, stack):
        fd = os.open(self.root, _DIR_FLAGS)
        stack.callback(os.close, fd)
        self._check_dir(fd, self.root)
        return fd

    def _open_dir(self, stack, root, name):
        try:
            fd = os.open(name, _DIR_FLAGS, dir_fd=root)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise SpoolError(f"spool {name}/ is not a real directory") from exc
            raise
        stack.callback(os.close, fd)
        self._check_dir(fd, name)
        return fd

    @staticmethod
    def _check_dir(fd, name):
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise SpoolError(f"spool {name} is not a directory")
        if st.st_mode & stat.S_IWOTH:
            raise SpoolError(f"spool {name} is world-writable")

    def _dirs(self, stack, *names):
        root = self._open_root(stack)
        return [self._open_dir(stack, root, name) for name in names]

    # -- reading -----------------------------------------------------------

    def _read_at(self, dirfd, name):
        """Read a bounded private copy of a regular file; returns (bytes, stat)."""
        try:
            fd = os.open(name, _READ_FLAGS, dir_fd=dirfd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise InvalidMessage("entry is a symbolic link") from exc
            raise
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise InvalidMessage("entry is not a regular file")
            if st.st_nlink > 2:
                # 1 = normal; 2 = transiently linked during ack/publish.
                raise InvalidMessage("entry has unexpected hard links")
            if self.expected_uids is not None and st.st_uid not in self.expected_uids:
                raise InvalidMessage(f"entry owned by unexpected uid {st.st_uid}")
            if st.st_size > self.max_message_bytes:
                raise InvalidMessage("entry exceeds message size limit")
            chunks, remaining = [], self.max_message_bytes + 1
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 1 << 20))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > self.max_message_bytes:
                raise InvalidMessage("entry exceeds message size limit")
            return raw, st
        finally:
            os.close(fd)

    def _parse(self, raw):
        try:
            return validate_manifest(loads(raw, self.max_message_bytes))
        except InvalidMessage:
            raise
        except ContractError as exc:
            raise InvalidMessage(str(exc)) from exc

    def scan(self, limit=100):
        """Oldest-first published entries, including invalid ones to be quarantined."""
        if limit < 1:
            raise ValueError("limit must be positive")
        entries = []
        with ExitStack() as stack:
            (new,) = self._dirs(stack, "new")
            with os.scandir(new) as it:
                for item in it:
                    try:
                        st = item.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    entries.append(Entry(item.name, st.st_size, st.st_mtime_ns,
                                         stat.S_ISREG(st.st_mode), self._valid_name(item.name)))
        entries.sort(key=lambda e: (e.mtime_ns, e.name))
        return entries[:limit]

    @staticmethod
    def _valid_name(name):
        return name.endswith(SUFFIX) and MESSAGE_ID.fullmatch(name[:-len(SUFFIX)]) is not None

    def read(self, entry, *, kinds=None, producers=None):
        """Validate an entry and return an immutable in-memory private copy."""
        name = entry.name if isinstance(entry, Entry) else entry
        if not self._valid_name(name):
            raise InvalidMessage("invalid entry name")
        with ExitStack() as stack:
            (new,) = self._dirs(stack, "new")
            raw, st = self._read_at(new, name)
        manifest = self._parse(raw)
        if name != manifest["message_id"] + SUFFIX:
            raise InvalidMessage("entry name does not match message_id")
        if kinds is not None and manifest["kind"] not in kinds:
            raise InvalidMessage(f"unexpected kind {manifest['kind']}")
        if producers is not None and manifest["producer"] not in producers:
            raise InvalidMessage(f"unexpected producer {manifest['producer']}")
        return Message(name, manifest["message_id"], manifest["kind"], manifest["producer"],
                       manifest["created_at"], manifest["content_sha256"], manifest["payload"],
                       hashlib.sha256(raw).hexdigest(), len(raw), st.st_mtime_ns,
                       st.st_dev, st.st_ino)

    # -- publication -------------------------------------------------------

    def publish(self, manifest, *, urgent=False):
        """Durably publish; returns only after file and directory entry are synced.

        Retrying an identical message (same ID, kind, producer and content hash)
        is idempotent even if ``created_at`` differs. A different message under an
        existing ID raises SpoolConflict and never overwrites.
        """
        validate_manifest(manifest)
        data = (canonical(manifest) + "\n").encode("ascii")
        if len(data) > self.max_message_bytes:
            raise SpoolFull("message exceeds size limit")
        name = manifest["message_id"] + SUFFIX
        with ExitStack() as stack:
            tmp, new = self._dirs(stack, "tmp", "new")
            existing = self._existing(new, name, manifest)
            if existing is not None:
                return existing
            self._check_quota(new, len(data), urgent)
            tmpname = f".{manifest['message_id']}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
            try:
                fd = os.open(tmpname, _CREATE_FLAGS, self.file_mode, dir_fd=tmp)
                try:
                    os.fchmod(fd, self.file_mode)
                    self._fault("publish.tmp_created")
                    view = memoryview(data)
                    while view:
                        view = view[os.write(fd, view):]
                    self._fault("publish.tmp_written")
                    os.fsync(fd)
                    self._fault("publish.tmp_synced")
                finally:
                    os.close(fd)
                try:
                    os.link(tmpname, name, src_dir_fd=tmp, dst_dir_fd=new, follow_symlinks=False)
                except FileExistsError:
                    existing = self._existing(new, name, manifest)
                    if existing is None:
                        raise SpoolConflict(f"{name} appeared and vanished during publication")
                    return existing
                self._fault("publish.linked")
                os.fsync(new)
                self._fault("publish.dir_synced")
            finally:
                try:
                    os.unlink(tmpname, dir_fd=tmp)
                except FileNotFoundError:
                    pass
        return Published(name, manifest["message_id"], manifest["content_sha256"], False)

    def _existing(self, new, name, manifest):
        try:
            raw, _ = self._read_at(new, name)
        except FileNotFoundError:
            return None
        except InvalidMessage as exc:
            raise SpoolConflict(f"{name} exists and is unreadable: {exc}") from exc
        try:
            current = self._parse(raw)
        except InvalidMessage as exc:
            raise SpoolConflict(f"{name} exists with invalid content: {exc}") from exc
        if not _same_message(current, manifest):
            raise SpoolConflict(f"{name} already published with different content")
        # A previous attempt may have crashed before syncing the directory.
        os.fsync(new)
        return Published(name, manifest["message_id"], manifest["content_sha256"], True)

    def _check_quota(self, new, size, urgent):
        quota = self.quota
        if quota is None:
            return
        files, total = 0, 0
        with os.scandir(new) as it:
            for item in it:
                try:
                    total += item.stat(follow_symlinks=False).st_size
                    files += 1
                except FileNotFoundError:
                    pass
        max_files = quota.max_files - (0 if urgent else quota.reserved_files)
        max_bytes = quota.max_bytes - (0 if urgent else quota.reserved_bytes)
        if files + 1 > max_files or total + size > max_bytes:
            raise SpoolFull("spool quota reached" + ("" if urgent else " (urgent reserve held back)"))
        vfs = os.fstatvfs(new)
        if vfs.f_bavail * vfs.f_frsize < quota.min_free_bytes + 2 * size:
            raise SpoolFull("insufficient free disk space")
        if vfs.f_files and vfs.f_favail < quota.min_free_inodes + 2:
            raise SpoolFull("insufficient free inodes")

    # -- consumption -------------------------------------------------------

    def acknowledge(self, message):
        """Archive a consumed message AFTER the consumer committed its effects.

        Idempotent: acknowledging an already archived message is a no-op. If the
        published entry was replaced since it was read, raises SpoolConflict and
        leaves it in place for re-reading (the consumer's dedup detects it).
        """
        archive = f"{message.message_id}.{message.content_sha256[:16]}{SUFFIX}"
        with ExitStack() as stack:
            new, done = self._dirs(stack, "new", "done")
            try:
                raw, st = self._read_at(new, message.name)
            except FileNotFoundError:
                return False
            except InvalidMessage as exc:
                raise SpoolConflict(f"{message.name} was replaced after it was read") from exc
            # Inode numbers are reused after deletion, so identity alone is not proof.
            if ((st.st_dev, st.st_ino) != (message.device, message.inode)
                    or hashlib.sha256(raw).hexdigest() != message.raw_sha256):
                raise SpoolConflict(f"{message.name} was replaced after it was read")
            try:
                os.link(message.name, archive, src_dir_fd=new, dst_dir_fd=done,
                        follow_symlinks=False)
            except FileExistsError:
                pass  # earlier interrupted acknowledgement; name embeds the content hash
            self._fault("ack.linked")
            os.fsync(done)
            self._fault("ack.archived")
            os.unlink(message.name, dir_fd=new)
            self._fault("ack.unlinked")
            os.fsync(new)
        return True

    def quarantine(self, entry, reason):
        """Move a rejected entry (any file type) out of new/ with a reason record."""
        name = entry.name if isinstance(entry, (Entry, Message)) else entry
        if "/" in name or name in (".", ".."):
            raise ValueError("invalid entry name")
        safe = name if self._valid_name(name) else (
            "invalid-" + hashlib.sha256(name.encode("utf-8", "surrogateescape")).hexdigest()[:16])
        target = f"{safe}.{time.time_ns()}.{secrets.token_hex(4)}"
        record = canonical({"schema_version": SCHEMA_VERSION, "original_name": name
                            if name.isprintable() else repr(name), "reason": str(reason)[:1024],
                            "quarantined_at": utc_now()}).encode("ascii") + b"\n"
        with ExitStack() as stack:
            new, quarantine = self._dirs(stack, "new", "quarantine")
            if self._count(quarantine, quarantined=True) >= self.max_quarantine:
                raise SpoolFull("quarantine full; poison input remains in new/")
            try:
                os.stat(name, dir_fd=new, follow_symlinks=False)
            except FileNotFoundError:
                return None
            fd = os.open(target + REASON_SUFFIX, _CREATE_FLAGS, 0o640, dir_fd=quarantine)
            try:
                os.write(fd, record)
                os.fsync(fd)
            finally:
                os.close(fd)
            self._fault("quarantine.reason_written")
            os.rename(name, target, src_dir_fd=new, dst_dir_fd=quarantine)
            self._fault("quarantine.moved")
            os.fsync(quarantine)
            os.fsync(new)
        return target

    # -- maintenance and health -------------------------------------------

    @staticmethod
    def _count(dirfd, quarantined=False):
        with os.scandir(dirfd) as it:
            return sum(1 for item in it
                       if not (quarantined and item.name.endswith(REASON_SUFFIX)))

    def stats(self):
        now = time.time_ns()
        files, total, oldest = 0, 0, None
        with ExitStack() as stack:
            new, quarantine = self._dirs(stack, "new", "quarantine")
            with os.scandir(new) as it:
                for item in it:
                    try:
                        st = item.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    files += 1
                    total += st.st_size
                    oldest = st.st_mtime_ns if oldest is None else min(oldest, st.st_mtime_ns)
            quarantined = self._count(quarantine, quarantined=True)
        age = None if oldest is None else max(0.0, (now - oldest) / 1e9)
        return Stats(files, total, age, quarantined)

    def cleanup_tmp(self, older_than_seconds):
        """Remove abandoned temporary files left by crashed producers."""
        return self._prune("tmp", older_than_seconds,
                           lambda n: n.startswith(".") and n.endswith(".tmp"))

    def prune_done(self, older_than_seconds):
        """Retention for acknowledged messages; callers apply the approved policy."""
        return self._prune("done", older_than_seconds, lambda n: n.endswith(SUFFIX))

    def _prune(self, subdir, older_than_seconds, match):
        cutoff = time.time_ns() - int(older_than_seconds * 1e9)
        removed = 0
        with ExitStack() as stack:
            (dirfd,) = self._dirs(stack, subdir)
            with os.scandir(dirfd) as it:
                for item in it:
                    try:
                        st = item.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if match(item.name) and stat.S_ISREG(st.st_mode) and st.st_mtime_ns < cutoff:
                        os.unlink(item.name, dir_fd=dirfd)
                        removed += 1
            if removed:
                os.fsync(dirfd)
        return removed
