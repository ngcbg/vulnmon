# Filesystem spool protocol v1

Implements architecture v0.3 §9.3–9.4. Reference implementation: `vulnmon.common.spool`. This document describes the hand-off mechanism; it does not by itself make any producer's data trustworthy.

## Spool layout

Each spool carries **one direction between one producer identity and one consumer identity** (e.g. inventory intake → core, notify → core). A single shared writable spool is not acceptable. All subdirectories are on one filesystem.

```text
<spool>/
    tmp/         producer-private temporary files
    new/         published manifests awaiting consumption
    done/        acknowledged manifests, kept until retention pruning
    quarantine/  rejected entries plus <name>.reason.json records
```

Ownership and modes are a deployment decision. They must make sure that only the producer can write `tmp/`, only the producer can create entries in `new/`, the consumer can remove entries from `new/`, and only the consumer can write `done/` and `quarantine/`. No spool directory may be world-writable (the implementation refuses one). Symlinked subdirectories are refused. The path leading up to `<spool>` must be trusted.

## Manifest envelope

One JSON object per file, named `<message_id>.json`, with the shape given in [manifest.schema.json](manifest.schema.json):

| Field | Meaning |
|---|---|
| `schema_version` | `1` |
| `message_id` | Stable producer-chosen ID, `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; a retry reuses it |
| `kind` | Dotted type, e.g. `inventory.snapshot`, `delivery.receipt`; consumers accept only configured kinds |
| `producer` | Declared producer; consumers check it against configuration. **Not authentication** |
| `created_at` | RFC 3339 timestamp with zone |
| `content_sha256` | SHA-256 of the canonical payload JSON (sorted keys, no whitespace, ASCII) |
| `payload` | Kind-specific object, validated by its own contract |

Parsing is strict: duplicate keys, `NaN`/`Infinity`, invalid UTF-8, excessive nesting and oversize input are rejected.

**Message identity** is `(message_id, kind, producer, content_sha256)`. `created_at` and serialization are not part of identity, so a rebuilt retry is still identical.

## Publication (producer)

1. Create `tmp/.<id>.<pid>.<random>.tmp` with `O_CREAT|O_EXCL|O_NOFOLLOW` and an explicit mode.
2. Write the complete bytes, `fsync()` the file and close it.
3. `link()` it to `new/<id>.json`. `link()` never replaces an existing name.
4. `fsync()` the `new/` directory.
5. Unlink the temporary file. Producers clean up stale temporaries later.

Publication counts as acknowledged only when step 4 has succeeded. Any error, including `ENOSPC` or a sync failure, is reported to the caller and never treated as success.

If `new/<id>.json` already exists:

- **Same identity:** the publish is an idempotent success. The directory is synced again, because an earlier attempt may have crashed before step 4.
- **Different identity, or unreadable:** `SpoolConflict`. The existing entry is never overwritten.

**Quotas are advisory.** Before publishing, the producer checks the file count, byte total, free space and free inodes. Capacity reserved for urgent work can be used only by a producer configured to treat the message as urgent. A priority label inside a manifest has no authority. Because the check is not atomic across concurrent producers, the real limit must come from filesystem quotas or separate mounts.

## Consumption (consumer)

1. **Scan** `new/` oldest first, without following symlinks. Invalid names, non-regular files and symlinks are returned too, so that they can be quarantined.
2. **Read** each entry relative to the directory handle (`O_NOFOLLOW|O_NONBLOCK`) and reject it unless:
   - it is a regular file;
   - it has at most 2 hard links;
   - its owner matches the expected UID, if one is configured;
   - it is within the size limit.

   The bytes are copied into memory, and only that private copy is validated and used. Then check the envelope, verify the content hash, and confirm that the file name matches `message_id`, the kind is allowed and the producer is allowed.
3. **Commit** the effects and an ingestion record keyed by message identity in the consumer's own durable state, in one transaction.
4. **Acknowledge.** Re-read the entry and confirm it has the same inode and the same raw SHA-256. Link it to `done/<id>.<sha16>.json` and `fsync(done/)`. Unlink it from `new/` and `fsync(new/)`.

| Crash point | Effect | Recovery |
|---|---|---|
| Before step 3 commits | Nothing was consumed | The entry is read again |
| Between step 3 and the end of step 4 | Effects are committed; the entry is still in `new/` | The entry is read again and the consumer's dedup turns it into a no-op. Acknowledging it again is idempotent |
| Entry replaced since step 2 | Step 4 raises `SpoolConflict`, and the entry is left in place | On the next read, the consumer's ingestion record catches the same ID with different content, and the entry is quarantined |

Disappearing from `new/` never means an entry was handled successfully. The consumer's committed state is the authority.

## Quarantine

Rejected entries are renamed into `quarantine/` under a unique name. The reason record is written and synced first. Both directories are then synced. Quarantine has a size limit: when it is full, quarantining fails with `SpoolFull` and the poison entry stays in `new/`. The caller must alert on that independently and must not loop on the entry.

## Health

`stats()` reports the pending count, the byte total, the age of the oldest pending entry (from the entry's mtime) and the number of quarantined entries. These are exported for the watchdog; the watchdog never reads the spool directly.

## Known limitations of v1

- Payloads are inline only. References to immutable blobs (raw evidence) are deferred until the evidence store exists.
- Acknowledgement re-checks the entry and then links it by name. There is a small time-of-check/time-of-use window, so consumer dedup by message identity remains mandatory.
- Ordering is by mtime, which is a best-effort publication time. Priority selection belongs to the core scheduler, not the spool.
- Durability relies on the kernel and storage honouring `fsync()`. Fault tests inject failures at every protocol step, but they do not simulate power loss. That must be validated on the target storage stack (architecture §15.1).
