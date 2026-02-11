"""Immune Propagator — Constraint Distribution.

Pushes new constraints to all tenants via in-memory pub/sub.
Interface-compatible with Redis for production deployment.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class PropagationEvent:
    """An event describing a constraint update to propagate."""

    event_id: str
    event_type: str              # "constraint_added", "constraint_updated", "constraint_removed"
    constraint_id: str
    constraint_yaml: str | None  # YAML content for added/updated
    source: str                  # "immune_system", "admin", "cve_feed"
    priority: str                # "critical", "high", "medium", "low"
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


# Type alias for subscriber callbacks
SubscriberCallback = Callable[[PropagationEvent], Awaitable[None]]


class ConstraintPropagator:
    """Distributes constraint updates to all subscribed tenants.

    In-memory implementation using asyncio. Production deployment
    swaps this for Redis pub/sub with the same interface.

    Propagation flow:
    1. Immune system generates a new constraint
    2. Propagator broadcasts the constraint to all subscribers
    3. Each tenant's constraint engine reloads with the new rule
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[SubscriberCallback]] = {}
        self._event_log: list[PropagationEvent] = []
        self._stats = {
            "total_events": 0,
            "total_deliveries": 0,
            "failed_deliveries": 0,
        }

    async def subscribe(
        self,
        tenant_id: str,
        callback: SubscriberCallback,
    ) -> None:
        """Subscribe a tenant to constraint updates.

        Args:
            tenant_id: The tenant's unique identifier.
            callback: Async function called when new constraints are published.
        """
        if tenant_id not in self._subscribers:
            self._subscribers[tenant_id] = []
        self._subscribers[tenant_id].append(callback)

        logger.info(
            "propagator.subscribed",
            tenant_id=tenant_id,
            total_subscribers=self._total_subscriber_count(),
        )

    async def unsubscribe(self, tenant_id: str) -> None:
        """Remove all subscriptions for a tenant."""
        self._subscribers.pop(tenant_id, None)
        logger.info("propagator.unsubscribed", tenant_id=tenant_id)

    async def publish(self, event: PropagationEvent) -> int:
        """Publish a constraint update to all subscribers.

        Returns the number of successful deliveries.
        """
        self._event_log.append(event)
        self._stats["total_events"] += 1

        delivered = 0
        tasks: list[asyncio.Task[None]] = []

        for tenant_id, callbacks in self._subscribers.items():
            for callback in callbacks:
                task = asyncio.create_task(
                    self._safe_deliver(tenant_id, callback, event)
                )
                tasks.append(task)

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            delivered = sum(1 for r in results if r is None)
            failed = sum(1 for r in results if isinstance(r, Exception))
            self._stats["total_deliveries"] += delivered
            self._stats["failed_deliveries"] += failed

        logger.info(
            "propagator.published",
            event_id=event.event_id,
            event_type=event.event_type,
            constraint_id=event.constraint_id,
            delivered=delivered,
            total_subscribers=self._total_subscriber_count(),
        )

        return delivered

    async def broadcast_constraint(
        self,
        constraint_id: str,
        constraint_yaml: str,
        source: str = "immune_system",
        priority: str = "medium",
    ) -> int:
        """Convenience: broadcast a new constraint to all tenants."""
        event = PropagationEvent(
            event_id=f"evt-{int(time.time() * 1000)}-{constraint_id}",
            event_type="constraint_added",
            constraint_id=constraint_id,
            constraint_yaml=constraint_yaml,
            source=source,
            priority=priority,
        )
        return await self.publish(event)

    async def broadcast_removal(
        self,
        constraint_id: str,
        source: str = "admin",
    ) -> int:
        """Broadcast the removal of a constraint."""
        event = PropagationEvent(
            event_id=f"evt-{int(time.time() * 1000)}-rm-{constraint_id}",
            event_type="constraint_removed",
            constraint_id=constraint_id,
            constraint_yaml=None,
            source=source,
            priority="high",
        )
        return await self.publish(event)

    async def get_event_log(
        self,
        limit: int = 100,
        event_type: str | None = None,
    ) -> list[PropagationEvent]:
        """Get recent propagation events."""
        events = self._event_log
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]

    async def get_stats(self) -> dict[str, Any]:
        """Get propagation statistics."""
        return {
            **self._stats,
            "active_subscribers": self._total_subscriber_count(),
            "tenant_count": len(self._subscribers),
        }

    async def _safe_deliver(
        self,
        tenant_id: str,
        callback: SubscriberCallback,
        event: PropagationEvent,
    ) -> None:
        """Safely deliver an event, catching and logging errors."""
        try:
            await asyncio.wait_for(callback(event), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning(
                "propagator.delivery_timeout",
                tenant_id=tenant_id,
                event_id=event.event_id,
            )
            raise
        except Exception as e:
            logger.error(
                "propagator.delivery_failed",
                tenant_id=tenant_id,
                event_id=event.event_id,
                error=str(e),
            )
            raise

    def _total_subscriber_count(self) -> int:
        return sum(len(cbs) for cbs in self._subscribers.values())
