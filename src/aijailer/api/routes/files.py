"""File operations API routes."""

import uuid

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.api.middleware.auth import AuthContext, authenticate
from aijailer.db.base import get_db
from aijailer.schemas.common import ApiResponse
from aijailer.schemas.files import FileEntry, FileListResponse
from aijailer.services.cell_service import CellService

router = APIRouter(prefix="/v1/cells/{cell_id}/files", tags=["Files"])


@router.post("/upload", status_code=201)
async def upload_file(
    cell_id: uuid.UUID,
    path: str = Form(...),
    file: UploadFile = File(...),
    mode: str = Form("0644"),
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    """Upload a file to a cell's filesystem.

    In production, this sends the file content to the Cell Agent via vsock.
    For the MVP, it acknowledges the upload.
    """
    svc = CellService(db)
    cell = await svc.get_cell(cell_id, auth.tenant_id)

    content = await file.read()
    return ApiResponse(
        data={
            "path": path,
            "size": len(content),
            "mode": mode,
            "message": "File uploaded successfully.",
        }
    )


@router.get("/download")
async def download_file(
    cell_id: uuid.UUID,
    path: str = Query(...),
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    """Download a file from a cell's filesystem.

    In production, this requests the file from the Cell Agent via vsock
    and streams it back to the client.
    """
    svc = CellService(db)
    cell = await svc.get_cell(cell_id, auth.tenant_id)

    # MVP: Return simulated content
    simulated_content = f"[simulated file content for {path}]".encode()

    async def _stream():
        yield simulated_content

    return StreamingResponse(
        _stream(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{path.split("/")[-1]}"'},
    )


@router.get("/list", response_model=ApiResponse[FileListResponse])
async def list_files(
    cell_id: uuid.UUID,
    path: str = Query("/"),
    recursive: bool = Query(False),
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    """List files in a directory inside a cell.

    In production, this queries the Cell Agent for a directory listing.
    """
    svc = CellService(db)
    cell = await svc.get_cell(cell_id, auth.tenant_id)

    # MVP: Return simulated directory listing
    return ApiResponse(
        data=FileListResponse(
            path=path,
            entries=[
                FileEntry(name=".", type="directory", permissions="0755"),
            ],
        )
    )
