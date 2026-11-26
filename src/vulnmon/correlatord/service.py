"""Application facade: CLI and future IPC use these typed domain operations."""
from vulnmon import inventoryd, inteld
from . import policy
from .matchers import reconcile
from .persistence.interface import Persistence, StaleBatch


class Core:
    def __init__(self, store: Persistence):
        self.store = store

    def ingest_inventory(self, snapshot):
        return self.store.ingest_inventory(inventoryd.validate(snapshot))

    def ingest_advisory(self, advisory):
        return self.store.ingest_advisory(inteld.validate(advisory))

    def correlate(self, batch_size=100, max_batches=1):
        if not 1 <= batch_size <= 500 or not 1 <= max_batches <= 1000:
            raise ValueError("batch size or batch count outside supported limits")
        evaluated = stale = 0
        for _ in range(max_batches):
            # Read and commit are separate lock units; evaluation (dpkg subprocesses)
            # runs with no lock or connection held.
            batch = self.store.next_batch(batch_size)
            if batch is None:
                break
            token, candidates = batch
            for item in candidates:
                match = reconcile(item["component"], item["advisories"])
                item.update(applicability=match.applicability.value, reason=match.reason,
                            priority=policy.priority(item["component"], match, item["advisories"]),
                            policy_version=policy.VERSION)
            try:
                self.store.commit_batch(token, candidates)
            except StaleBatch:
                stale += 1  # discarded; the pending job is re-read on the next iteration
                continue
            evaluated += len(candidates)
            if not candidates:
                break
        return {"evaluated": evaluated, "stale_batches": stale, "status": self.store.status()}
