"""Test simulated MicroVM engine."""

import uuid

import pytest

from aijailer.engine.microvm import SimulatedMicroVMEngine, VMConfig, VMStatus


@pytest.mark.asyncio
async def test_create_and_destroy_vm():
    engine = SimulatedMicroVMEngine()
    cell_id = uuid.uuid4()

    config = VMConfig(cell_id=cell_id, image="base-python", vcpus=2, memory_mb=1024)
    info = await engine.create_vm(config)

    assert info.status == VMStatus.RUNNING
    assert info.internal_ip is not None

    await engine.destroy_vm(cell_id)
    info = await engine.get_vm_info(cell_id)
    assert info.status == VMStatus.DESTROYED


@pytest.mark.asyncio
async def test_pause_resume_vm():
    engine = SimulatedMicroVMEngine()
    cell_id = uuid.uuid4()

    config = VMConfig(cell_id=cell_id, image="base-python")
    await engine.create_vm(config)

    await engine.pause_vm(cell_id)
    info = await engine.get_vm_info(cell_id)
    assert info.status == VMStatus.PAUSED

    await engine.resume_vm(cell_id)
    info = await engine.get_vm_info(cell_id)
    assert info.status == VMStatus.RUNNING


@pytest.mark.asyncio
async def test_exec_command():
    engine = SimulatedMicroVMEngine()
    cell_id = uuid.uuid4()

    config = VMConfig(cell_id=cell_id, image="base-python")
    await engine.create_vm(config)

    result = await engine.exec_command(cell_id, "echo hello")
    assert result.exit_code == 0
    assert "echo hello" in result.stdout
