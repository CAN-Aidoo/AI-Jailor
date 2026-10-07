"""Group-commit for audit events that are high-volume and individually low-stakes (per-request
network decisions). Callers ``submit`` synchronously (no await, no task per event); a background
writer commits everything pending in one transaction, either when ``max_events`` have piled up or
``max_delay`` seconds after the oldest was submitted.

What batching costs, stated plainly:
  * a hard crash loses whatever is still queued (at most ``max_delay`` of events). Events that must
    survive a crash are recorded with ``record_event`` (durable on return), never ``submit``;
  * when the queue is full the NEWEST submissions are dropped, and the drop is made visible in the
    chain itself as an ``audit_events_dropped`` marker plus a counter (metric + log): a gap is
    never silent;
  * if the database is down the batch is kept (up to the queue bound) and retried with backoff.

Event order within a chain is preserved, and a durable ``record_event`` flushes the queue first, so
a chain's order always matches the order things happened."""

import asyncio
import collections
import uuid
from collections.abc import Awaitable, Callable

import structlog

logger = structlog.get_logger(__name__)

BuildFn = Callable[[str], object]
Item = tuple[uuid.UUID, uuid.UUID, BuildFn]


class AuditBatcher:
    def __init__(self, write: Callable[[list[Item]], Awaitable[list]],
                 make_marker: Callable[[uuid.UUID, uuid.UUID, int], BuildFn],
                 max_events: int = 200, max_delay: float = 0.5, queue_max: int = 10_000,
                 retry_delay: float = 1.0) -> None:
        self._write, self._make_marker = write, make_marker
        self.max_events, self.max_delay = max_events, max_delay
        self.queue_max, self._retry_delay = queue_max, retry_delay
        self._q: collections.deque[Item] = collections.deque()
        self._dropped: dict[tuple, int] = {}
        self._wake = asyncio.Event()
        self._full = asyncio.Event()
        self._idle = asyncio.Event()
        self._idle.set()
        self._flush_lock = asyncio.Lock()
        self._task: asyncio.Task | None = None
        self._closing = False
        # counters (exported as metrics)
        self.dropped_total = 0
        self.flushed_total = 0
        self.flushes_total = 0
        self.flush_failures_total = 0

    @property
    def pending(self) -> int:
        return len(self._q)

    def submit(self, tenant_id: uuid.UUID, cell_id: uuid.UUID, build: BuildFn) -> bool:
        """Queue an event. Never blocks, never raises for capacity. False if it was dropped."""
        if self._closing:
            return False
        if len(self._q) >= self.queue_max:
            key = (tenant_id, cell_id)
            self._dropped[key] = self._dropped.get(key, 0) + 1
            self.dropped_total += 1
            if self.dropped_total == 1 or self.dropped_total % 1000 == 0:
                logger.error("audit.batch_queue_full_dropping", dropped_total=self.dropped_total,
                             queue_max=self.queue_max)
            return False
        self._q.append((tenant_id, cell_id, build))
        self._idle.clear()
        self._wake.set()
        if len(self._q) >= self.max_events:
            self._full.set()
        self._ensure_running()
        return True

    def _ensure_running(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.get_running_loop().create_task(self._run())

    async def _run(self) -> None:
        while not self._closing:
            await self._wake.wait()
            try:                      # let a batch accumulate, unless it is already big enough
                await asyncio.wait_for(self._full.wait(), self.max_delay)
            except TimeoutError:
                pass
            self._wake.clear()
            self._full.clear()
            try:
                await self.flush()
            except Exception:
                # flush() already requeued the batch; back off, then try again
                await asyncio.sleep(self._retry_delay)
                if self._q:
                    self._wake.set()

    async def flush(self) -> None:
        """Write everything queued so far (and anything submitted while writing). Raises if the
        write fails; the batch stays queued, so a later flush retries it."""
        async with self._flush_lock:
            while self._q or self._dropped:
                dropped, self._dropped = self._dropped, {}
                batch: list[Item] = []
                for (t, c), n in dropped.items():     # the gap, recorded where it happened
                    batch.append((t, c, self._make_marker(t, c, n)))
                while self._q and len(batch) < self.max_events:
                    batch.append(self._q.popleft())
                try:
                    await self._write(batch)
                except BaseException:
                    self.flush_failures_total += 1
                    # put it back in front, in order (the markers are re-derived from the counters)
                    for item in reversed(batch[len(dropped):]):
                        self._q.appendleft(item)
                    for k, n in dropped.items():
                        self._dropped[k] = self._dropped.get(k, 0) + n
                    logger.exception("audit.batch_flush_failed", pending=len(self._q))
                    raise
                self.flushes_total += 1
                self.flushed_total += len(batch)
            self._idle.set()

    async def close(self, timeout: float = 10.0) -> None:
        """Stop accepting events and write what is queued (bounded by ``timeout``)."""
        self._closing = True
        self._wake.set()
        self._full.set()
        if self._task is not None:
            # Let the writer finish what it is doing (cancelling mid-commit could duplicate it).
            try:
                await asyncio.wait_for(asyncio.shield(self._task), timeout)
            except Exception:
                pass
        try:
            await asyncio.wait_for(self.flush(), timeout)
        except Exception:
            logger.error("audit.batch_close_lost_events", lost=len(self._q))
