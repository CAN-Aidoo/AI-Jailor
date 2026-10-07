"""Peer link lifecycle: propose -> accept -> (use) -> revoke/expire, with a transactional audit trail.

Consent is two-sided: the tenant that owns the initiator cell proposes, the tenant that owns the
responder cell accepts (links between two cells of ONE tenant need no second consent). A link only
works while it is active, unexpired, and BOTH cells are running; the relay re-checks all of that on
every connection, so a lapsed, revoked or stopped side cannot reconnect and nothing depends on a
cleanup job having run."""

import uuid
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.core.config import get_settings
from aijailer.core.exceptions import AiJailerError
from aijailer.models.audit import EventType, Severity
from aijailer.models.cell import Cell
from aijailer.models.peer_link import PeerLink
from aijailer.peerlink.hub import PeerAuth
from aijailer.services.audit_service import get_audit_service

logger = structlog.get_logger(__name__)

LIVE_FOR_PEERING = ("running", "ready")
PURPOSE_MAX = 64


def _err(message: str, code: str) -> AiJailerError:
    return AiJailerError(message, code=code)


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=UTC)


def _now() -> datetime:
    return datetime.now(UTC)


class PeerLinkService:
    def __init__(self, db: AsyncSession, hub=None):
        self.db = db
        self.hub = hub
        self.audit = get_audit_service()

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def require_enabled() -> None:
        if not get_settings().peer_attestation_secret:
            raise _err("peer links are not enabled on this deployment", "peer_links_disabled")

    async def _cell(self, cell_id: uuid.UUID) -> Cell | None:
        return (await self.db.execute(select(Cell).where(Cell.id == cell_id))).scalar_one_or_none()

    async def _audit(self, tenant_id: uuid.UUID, cell_id: uuid.UUID, action: str, link: PeerLink,
                     **extra) -> None:
        """Inside this transaction: the state change and its record commit together."""
        await self.audit.record_event(
            tenant_id=tenant_id, cell_id=cell_id, event_type=EventType.LIFECYCLE,
            severity=Severity.WARNING,
            details={"action": action, "link_id": link.id.hex,
                     "initiator_cell_id": str(link.initiator_cell_id),
                     "responder_cell_id": str(link.responder_cell_id), **extra},
            session=self.db)

    async def get(self, tenant_id: uuid.UUID, link_id: uuid.UUID) -> PeerLink:
        """Only a party to the link can see it; everyone else gets the same 404."""
        link = (await self.db.execute(select(PeerLink).where(PeerLink.id == link_id))).scalar_one_or_none()
        if link is None or tenant_id not in (link.initiator_tenant_id, link.responder_tenant_id):
            raise _err("peer link not found", "peer_link_not_found")
        return link

    async def list_links(self, tenant_id: uuid.UUID, include_inactive: bool = False) -> list[PeerLink]:
        q = select(PeerLink).where(or_(PeerLink.initiator_tenant_id == tenant_id,
                                       PeerLink.responder_tenant_id == tenant_id))
        if not include_inactive:
            q = q.where(PeerLink.status != "revoked", PeerLink.expires_at > _now())
        return list((await self.db.execute(q.order_by(PeerLink.created_at.desc()))).scalars())

    # ------------------------------------------------------------------ propose / accept / revoke
    async def propose(self, tenant_id: uuid.UUID, cell_id: uuid.UUID, peer_cell_id: uuid.UUID,
                      ttl_seconds: int | None = None, purpose: str | None = None) -> PeerLink:
        self.require_enabled()
        s = get_settings()
        ttl = ttl_seconds or s.peer_link_default_ttl_seconds
        if not (60 <= ttl <= s.peer_link_max_ttl_seconds):
            raise _err(f"ttl_seconds must be between 60 and {s.peer_link_max_ttl_seconds}",
                       "peer_link_invalid")
        if purpose is not None and (len(purpose) > PURPOSE_MAX or not purpose.isprintable()):
            raise _err(f"purpose must be printable text of at most {PURPOSE_MAX} characters",
                       "peer_link_invalid")
        if cell_id == peer_cell_id:
            raise _err("a cell cannot be linked to itself", "peer_link_invalid")
        mine = await self._cell(cell_id)
        if mine is None or mine.tenant_id != tenant_id:
            raise _err("cell not found", "cell_not_found")
        peer = await self._cell(peer_cell_id)
        # Same answer for "no such cell" and "not usable": do not let tenants probe for cell ids.
        if peer is None or peer.status not in LIVE_FOR_PEERING or mine.status not in LIVE_FOR_PEERING:
            raise _err("both cells must exist and be running", "peer_link_invalid")
        open_count = (await self.db.execute(select(func.count()).select_from(PeerLink).where(
            or_(PeerLink.initiator_tenant_id == tenant_id, PeerLink.responder_tenant_id == tenant_id),
            PeerLink.status != "revoked", PeerLink.expires_at > _now()))).scalar_one()
        if open_count >= s.peer_link_max_open_per_tenant:
            raise _err("too many open peer links", "peer_link_limit")
        dup = (await self.db.execute(select(PeerLink.id).where(
            PeerLink.status != "revoked", PeerLink.expires_at > _now(),
            or_((PeerLink.initiator_cell_id == cell_id) & (PeerLink.responder_cell_id == peer_cell_id),
                (PeerLink.initiator_cell_id == peer_cell_id) & (PeerLink.responder_cell_id == cell_id))
        ))).first()
        if dup is not None:
            raise _err("these cells already have an open peer link", "peer_link_conflict")
        same_tenant = peer.tenant_id == tenant_id
        now = _now()
        link = PeerLink(
            initiator_tenant_id=tenant_id, initiator_cell_id=cell_id,
            responder_tenant_id=peer.tenant_id, responder_cell_id=peer_cell_id,
            status="active" if same_tenant else "pending", purpose=purpose,
            accepted_at=now if same_tenant else None, expires_at=now + timedelta(seconds=ttl))
        self.db.add(link)
        await self.db.flush()
        await self._audit(tenant_id, cell_id, "peer_link_proposed", link, purpose=purpose,
                          auto_accepted=same_tenant)
        if not same_tenant:     # the other party's own chain shows that someone asked
            await self._audit(peer.tenant_id, peer_cell_id, "peer_link_requested", link,
                              from_tenant_id=str(tenant_id), purpose=purpose)
        return link

    async def accept(self, tenant_id: uuid.UUID, link_id: uuid.UUID) -> PeerLink:
        self.require_enabled()
        link = await self.get(tenant_id, link_id)
        if link.responder_tenant_id != tenant_id:
            raise _err("only the tenant that owns the responder cell can accept", "peer_link_invalid")
        if link.status != "pending" or _aware(link.expires_at) <= _now():
            raise _err("this link is not awaiting acceptance", "peer_link_invalid")
        cell = await self._cell(link.responder_cell_id)
        if cell is None or cell.status not in LIVE_FOR_PEERING:
            raise _err("the responder cell is not running", "peer_link_invalid")
        link.status, link.accepted_at = "active", _now()
        await self.db.flush()
        await self._audit(tenant_id, link.responder_cell_id, "peer_link_accepted", link)
        await self._audit(link.initiator_tenant_id, link.initiator_cell_id, "peer_link_accepted", link,
                          accepted_by_tenant_id=str(tenant_id))
        return link

    async def revoke(self, tenant_id: uuid.UUID, link_id: uuid.UUID) -> PeerLink:
        """Either party can end it at any time; a live session is cut immediately."""
        link = await self.get(tenant_id, link_id)
        if link.status != "revoked":
            link.status, link.revoked_at, link.revoked_by_tenant_id = "revoked", _now(), tenant_id
            await self.db.flush()
            # Both parties' chains record it (once, if both cells belong to the same tenant).
            sides = [(link.initiator_tenant_id, link.initiator_cell_id)]
            if link.responder_tenant_id != link.initiator_tenant_id:
                sides.append((link.responder_tenant_id, link.responder_cell_id))
            for owner, cell in sides:
                await self._audit(owner, cell, "peer_link_revoked", link,
                                  revoked_by_tenant_id=str(tenant_id))
            if self.hub is not None:
                self.hub.revoke_link(link.id.hex)
        return link

    async def revoke_for_cell(self, cell_id: uuid.UUID) -> int:
        """A cell that is stopped or destroyed loses its links (called from the cell lifecycle)."""
        links = (await self.db.execute(select(PeerLink).where(
            PeerLink.status != "revoked",
            or_(PeerLink.initiator_cell_id == cell_id, PeerLink.responder_cell_id == cell_id)))).scalars().all()
        for link in links:
            link.status, link.revoked_at = "revoked", _now()
            if self.hub is not None:
                self.hub.revoke_link(link.id.hex)
        if links:
            await self.db.flush()
            for link in links:
                owner = (link.initiator_tenant_id if link.initiator_cell_id == cell_id
                         else link.responder_tenant_id)
                await self._audit(owner, cell_id, "peer_link_revoked", link, reason="cell stopped or destroyed")
        return len(links)


async def authorize_attach(link_id_hex: str, cell_id: str) -> PeerAuth | None:
    """The hub's question: may THIS cell (known from the listener it connected to) attach to this
    link right now? Own short session, read-only. None for every kind of 'no'."""
    from aijailer.db.base import async_session_factory
    try:
        link_id, cell_uuid = uuid.UUID(hex=link_id_hex), uuid.UUID(cell_id)
    except ValueError:
        return None
    async with async_session_factory() as db:
        link = (await db.execute(select(PeerLink).where(PeerLink.id == link_id))).scalar_one_or_none()
        if link is None or link.status != "active" or _aware(link.expires_at) <= _now():
            return None
        if cell_uuid == link.initiator_cell_id:
            role, me, peer, my_tenant, peer_tenant = ("initiator", link.initiator_cell_id,
                                                      link.responder_cell_id, link.initiator_tenant_id,
                                                      link.responder_tenant_id)
        elif cell_uuid == link.responder_cell_id:
            role, me, peer, my_tenant, peer_tenant = ("responder", link.responder_cell_id,
                                                      link.initiator_cell_id, link.responder_tenant_id,
                                                      link.initiator_tenant_id)
        else:
            return None
        rows = (await db.execute(select(Cell.id, Cell.status, Cell.tenant_id).where(
            Cell.id.in_([me, peer])))).all()
        by_id = {r[0]: r for r in rows}
        for cid, tenant in ((me, my_tenant), (peer, peer_tenant)):     # both live, still owned as agreed
            row = by_id.get(cid)
            if row is None or row[1] not in LIVE_FOR_PEERING or row[2] != tenant:
                return None
        return PeerAuth(link_id_hex, role, str(me), str(my_tenant), str(peer), str(peer_tenant))
