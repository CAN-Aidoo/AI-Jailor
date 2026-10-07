"""Command and script execution service.

Manages executing commands and scripts inside running cells, with
MicroVM engine integration, audit logging, and resource metering.
"""

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.core.config import get_settings
from aijailer.core.exec_env import validate_exec_environment
from aijailer.core.exceptions import (
    CellNotRunningError,
    ExecutionTimeoutError,
    PolicyViolationError,
)
from aijailer.engine.microvm import get_microvm_engine
from aijailer.models.audit import EventType, Severity
from aijailer.models.cell import Cell
from aijailer.models.execution import Execution
from aijailer.services.audit_service import get_audit_service
from aijailer.services.cell_service import CellService
from aijailer.services.certificate_generator import get_certificate_generator
from aijailer.services.execution_gate import ExecutionGate
from aijailer.services.resource_service import get_resource_governor

logger = structlog.get_logger(__name__)


class ExecutionService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.cell_service = CellService(db)
        self.engine = get_microvm_engine()
        self.audit = get_audit_service()
        self.governor = get_resource_governor()

    async def execute_command(
        self,
        cell_id: uuid.UUID,
        tenant_id: uuid.UUID,
        command: str,
        timeout_seconds: int = 30,
        user: str = "agent",
        working_directory: str | None = None,
        environment: dict | None = None,
        api_key_id: uuid.UUID | None = None,
        request_id: str | None = None,
    ) -> Execution:
        """Execute a single command inside a cell.

        Steps:
        1. Validate cell is in running state
        2. Persist execution record (status: running)
        3. Send command to MicroVM engine
        4. Record result, audit event, and resource usage
        """
        environment = validate_exec_environment(environment)     # before anything is persisted
        cell = await self.cell_service.get_cell(cell_id, tenant_id)
        if cell.status != "running":
            raise CellNotRunningError(str(cell_id), cell.status)

        execution = Execution(
            cell_id=cell_id,
            tenant_id=tenant_id,
            command=command,
            timeout_seconds=timeout_seconds,
            user_context=user,
            working_directory=working_directory or cell.working_directory,
            environment=environment or {},
            api_key_id=api_key_id,
            request_id=request_id,
            status="running",
        )
        self.db.add(execution)
        await self.db.flush()

        logger.info(
            "execution.started",
            execution_id=str(execution.id),
            cell_id=str(cell_id),
            command=command[:200],
            timeout=timeout_seconds,
        )

        # Execute via MicroVM engine
        try:
            result = await self.engine.exec_command(
                cell_id=cell_id,
                command=command,
                timeout=timeout_seconds,
                user=user,
                env=environment,
            )

            execution.status = "completed"
            execution.exit_code = result.exit_code
            execution.stdout = result.stdout
            execution.stderr = result.stderr
            execution.completed_at = datetime.now(timezone.utc)
            execution.duration_ms = result.duration_ms
            execution.cpu_ms = result.cpu_ms
            execution.memory_peak_mb = result.memory_peak_mb

            logger.info(
                "execution.completed",
                execution_id=str(execution.id),
                exit_code=result.exit_code,
                duration_ms=result.duration_ms,
            )

        except TimeoutError:
            execution.status = "timeout"
            execution.completed_at = datetime.now(timezone.utc)
            logger.warning(
                "execution.timeout",
                execution_id=str(execution.id),
                timeout=timeout_seconds,
            )

        except Exception as e:
            execution.status = "failed"
            execution.stderr = str(e)
            execution.completed_at = datetime.now(timezone.utc)
            logger.error(
                "execution.failed",
                execution_id=str(execution.id),
                error=str(e),
            )

        # Record audit event
        await self.audit.record_event(
            tenant_id=tenant_id,
            cell_id=cell_id,
            event_type=EventType.EXECUTION,
            severity=Severity.WARNING if execution.exit_code != 0 else Severity.INFO,
            details={
                "execution_id": str(execution.id),
                "command": command[:500],
                "exit_code": execution.exit_code,
                "duration_ms": execution.duration_ms,
                "status": execution.status,
            },
            api_key_id=api_key_id,
            request_id=request_id,
        )

        # Record resource usage
        await self.governor.record_usage(
            cell_id=cell_id,
            tenant_id=tenant_id,
            cpu_seconds=(execution.cpu_ms or 0) / 1000.0,
            memory_gb_seconds=((execution.memory_peak_mb or 0) / 1024.0)
            * ((execution.duration_ms or 0) / 1000.0),
            api_calls=1,
        )

        return execution

    async def execute_script(
        self,
        cell_id: uuid.UUID,
        tenant_id: uuid.UUID,
        script: str,
        interpreter: str = "/bin/bash",
        timeout_seconds: int = 60,
        api_key_id: uuid.UUID | None = None,
        request_id: str | None = None,
    ) -> Execution:
        """Execute a multi-line script inside a cell.

        The script is written to a temp file inside the cell, then
        executed with the specified interpreter.
        """
        cell = await self.cell_service.get_cell(cell_id, tenant_id)
        if cell.status != "running":
            raise CellNotRunningError(str(cell_id), cell.status)

        gate_mode = get_settings().execution_gate_mode
        if gate_mode != "off":
            language = "python" if "python" in interpreter else "bash"
            decision = ExecutionGate(get_certificate_generator(),
                                     enforce=gate_mode == "enforce").decide(script, language)
            logger.info("execution.gate", cell_id=str(cell_id), tier=int(decision.tier),
                        basis=decision.basis, blocked=decision.blocked, reasons=decision.reasons)
            if decision.blocked:
                raise PolicyViolationError(
                    "script rejected by execution gate: " + "; ".join(decision.reasons[:3]))

        execution = Execution(
            cell_id=cell_id,
            tenant_id=tenant_id,
            command=script,
            interpreter=interpreter,
            timeout_seconds=timeout_seconds,
            api_key_id=api_key_id,
            request_id=request_id,
            status="running",
        )
        self.db.add(execution)
        await self.db.flush()

        logger.info(
            "execution.script_started",
            execution_id=str(execution.id),
            cell_id=str(cell_id),
            interpreter=interpreter,
            script_length=len(script),
        )

        # Execute script via engine (wraps as command with interpreter)
        try:
            # In production: write script to tmpfile, exec via interpreter
            # For MVP: the engine simulates execution
            full_command = f'{interpreter} -c {repr(script)}'
            result = await self.engine.exec_command(
                cell_id=cell_id,
                command=full_command,
                timeout=timeout_seconds,
                user="agent",
            )

            execution.status = "completed"
            execution.exit_code = result.exit_code
            execution.stdout = result.stdout
            execution.stderr = result.stderr
            execution.completed_at = datetime.now(timezone.utc)
            execution.duration_ms = result.duration_ms
            execution.cpu_ms = result.cpu_ms
            execution.memory_peak_mb = result.memory_peak_mb

            logger.info(
                "execution.script_completed",
                execution_id=str(execution.id),
                exit_code=result.exit_code,
                duration_ms=result.duration_ms,
            )

        except TimeoutError:
            execution.status = "timeout"
            execution.completed_at = datetime.now(timezone.utc)
            logger.warning(
                "execution.script_timeout",
                execution_id=str(execution.id),
                timeout=timeout_seconds,
            )

        except Exception as e:
            execution.status = "failed"
            execution.stderr = str(e)
            execution.completed_at = datetime.now(timezone.utc)
            logger.error(
                "execution.script_failed",
                execution_id=str(execution.id),
                error=str(e),
            )

        # Audit
        await self.audit.record_event(
            tenant_id=tenant_id,
            cell_id=cell_id,
            event_type=EventType.EXECUTION,
            severity=Severity.WARNING if execution.exit_code != 0 else Severity.INFO,
            details={
                "execution_id": str(execution.id),
                "interpreter": interpreter,
                "script_length": len(script),
                "exit_code": execution.exit_code,
                "duration_ms": execution.duration_ms,
                "status": execution.status,
            },
            api_key_id=api_key_id,
            request_id=request_id,
        )

        # Resource usage
        await self.governor.record_usage(
            cell_id=cell_id,
            tenant_id=tenant_id,
            cpu_seconds=(execution.cpu_ms or 0) / 1000.0,
            memory_gb_seconds=((execution.memory_peak_mb or 0) / 1024.0)
            * ((execution.duration_ms or 0) / 1000.0),
            api_calls=1,
        )

        return execution

    async def cancel_execution(
        self, cell_id: uuid.UUID, execution_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> None:
        """Cancel a running execution."""
        result = await self.db.execute(
            select(Execution).where(
                Execution.id == execution_id,
                Execution.cell_id == cell_id,
                Execution.tenant_id == tenant_id,
            )
        )
        execution = result.scalar_one_or_none()
        if execution and execution.status == "running":
            execution.status = "cancelled"
            execution.completed_at = datetime.now(timezone.utc)

            logger.info(
                "execution.cancelled",
                execution_id=str(execution_id),
                cell_id=str(cell_id),
            )

            await self.audit.record_event(
                tenant_id=tenant_id,
                cell_id=cell_id,
                event_type=EventType.EXECUTION,
                severity=Severity.WARNING,
                details={
                    "execution_id": str(execution_id),
                    "action": "cancelled",
                },
            )

    async def list_executions(
        self,
        cell_id: uuid.UUID,
        tenant_id: uuid.UUID,
        status: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> list[Execution]:
        """List execution history for a cell."""
        query = (
            select(Execution)
            .where(
                Execution.cell_id == cell_id,
                Execution.tenant_id == tenant_id,
            )
            .order_by(Execution.started_at.desc())
            .limit(limit)
        )

        if status:
            query = query.where(Execution.status == status)

        if cursor:
            query = query.where(Execution.started_at < cursor)

        result = await self.db.execute(query)
        return list(result.scalars().all())
