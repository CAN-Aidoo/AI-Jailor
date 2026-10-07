"""Peer links: let two cells talk end-to-end encrypted through the platform.

Two-sided consent (propose / accept), expiring, revocable by either party. See PEER_LINKS.md."""

import base64
import uuid

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.api.middleware.auth import AuthContext, require_role
from aijailer.db.base import get_db
from aijailer.netpolicy.runtime import get_peer_hub
from aijailer.peerlink.attest import PREDICATE_TYPE
from aijailer.peerlink.service import PeerLinkService
from aijailer.schemas.common import ApiResponse

router = APIRouter(prefix="/v1/peer-links", tags=["Peer links"])

WRITERS = ("owner", "admin")
READERS = ("owner", "admin", "auditor")


class ProposeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cell_id: uuid.UUID                       # your cell (the initiator / TLS client)
    peer_cell_id: uuid.UUID                  # the other cell, shared with you out of band
    ttl_seconds: StrictInt | None = None
    purpose: str | None = Field(default=None, max_length=64)


def _view(link, tenant_id: uuid.UUID) -> dict:
    mine = link.initiator_tenant_id == tenant_id
    return {
        "id": str(link.id), "status": link.status, "purpose": link.purpose,
        "my_role": "initiator" if mine else "responder",
        "my_cell_id": str(link.initiator_cell_id if mine else link.responder_cell_id),
        "peer_cell_id": str(link.responder_cell_id if mine else link.initiator_cell_id),
        "peer_tenant_id": str(link.responder_tenant_id if mine else link.initiator_tenant_id),
        # what the workload connects to through its proxy (CONNECT), and passes to aijailer-peer
        "connect_host": f"{link.id.hex}.peer.aijailer.invalid",
        "link_id": link.id.hex,
        "created_at": link.created_at.isoformat() if link.created_at else None,
        "accepted_at": link.accepted_at.isoformat() if link.accepted_at else None,
        "expires_at": link.expires_at.isoformat(),
        "revoked_at": link.revoked_at.isoformat() if link.revoked_at else None,
    }


def _svc(db: AsyncSession) -> PeerLinkService:
    PeerLinkService.require_enabled()
    return PeerLinkService(db, get_peer_hub())


@router.get("/attestation-key", response_model=ApiResponse[dict])
async def attestation_key(auth: AuthContext = Depends(require_role(*READERS))):
    """The platform's public key for peer attestations (also injected into every cell as
    ``AIJAILER_PEER_ATTEST_PUBKEY``). Verify attestations with it, or pin your peer's certificate
    hash and do not rely on the platform's word at all."""
    PeerLinkService.require_enabled()
    hub = get_peer_hub()
    raw = hub._signer.public_key.public_bytes(serialization.Encoding.Raw,
                                              serialization.PublicFormat.Raw)
    return ApiResponse(data={"keyid": hub._signer.keyid, "algorithm": "ed25519",
                             "public_key": base64.b64encode(raw).decode(),
                             "predicate_type": PREDICATE_TYPE})


@router.post("", status_code=201, response_model=ApiResponse[dict])
async def propose(body: ProposeRequest, auth: AuthContext = Depends(require_role(*WRITERS)),
                  db: AsyncSession = Depends(get_db)):
    """Propose a link from one of YOUR cells to another cell (any tenant). The other tenant must
    accept before it works, unless both cells are yours."""
    link = await _svc(db).propose(auth.tenant_id, body.cell_id, body.peer_cell_id,
                                  body.ttl_seconds, body.purpose)
    await db.commit()                        # the link and its audit records are durable together
    return ApiResponse(data=_view(link, auth.tenant_id))


@router.get("", response_model=ApiResponse[list[dict]])
async def list_links(include_inactive: bool = False,
                     auth: AuthContext = Depends(require_role(*READERS)),
                     db: AsyncSession = Depends(get_db)):
    """Links you are a party to (incoming proposals included). Revoked and expired are hidden
    unless ``include_inactive``."""
    links = await _svc(db).list_links(auth.tenant_id, include_inactive)
    return ApiResponse(data=[_view(link, auth.tenant_id) for link in links])


@router.get("/{link_id}", response_model=ApiResponse[dict])
async def get_link(link_id: uuid.UUID, auth: AuthContext = Depends(require_role(*READERS)),
                   db: AsyncSession = Depends(get_db)):
    return ApiResponse(data=_view(await _svc(db).get(auth.tenant_id, link_id), auth.tenant_id))


@router.post("/{link_id}/accept", response_model=ApiResponse[dict])
async def accept(link_id: uuid.UUID, auth: AuthContext = Depends(require_role(*WRITERS)),
                 db: AsyncSession = Depends(get_db)):
    """Accept a proposal made to one of your cells. Only the responder cell's tenant can."""
    link = await _svc(db).accept(auth.tenant_id, link_id)
    await db.commit()
    return ApiResponse(data=_view(link, auth.tenant_id))


@router.delete("/{link_id}", response_model=ApiResponse[dict])
async def revoke(link_id: uuid.UUID, auth: AuthContext = Depends(require_role(*WRITERS)),
                 db: AsyncSession = Depends(get_db)):
    """End the link now (either party). A live session is cut immediately."""
    link = await _svc(db).revoke(auth.tenant_id, link_id)
    await db.commit()
    return ApiResponse(data=_view(link, auth.tenant_id))



