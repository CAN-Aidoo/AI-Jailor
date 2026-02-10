"""Database seed script — creates default data for development.

Run with:  python -m aijailer.db.seed
"""

import asyncio
import hashlib
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.db.base import async_session_factory, engine, Base
from aijailer.models.tenant import ApiKey, Tenant, User
from aijailer.models.policy import SecurityPolicy

# Import all models to register them with Base.metadata
from aijailer.models.cell import Cell  # noqa: F401
from aijailer.models.execution import Execution  # noqa: F401
from aijailer.models.snapshot import Snapshot, PersistentVolume  # noqa: F401
from aijailer.models.node import Node  # noqa: F401
from aijailer.models.webhook import Webhook  # noqa: F401


async def create_tables():
    """Create all database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("[+] Database tables created.")


async def seed_data():
    """Seed development data."""
    async with async_session_factory() as db:
        # --- Admin tenant ---
        admin_tenant = Tenant(
            name="AI Jailer Admin",
            slug="aijailer-admin",
            status="active",
            tier="enterprise",
            max_concurrent_cells=1000,
            max_persistent_storage_gb=1000,
            max_snapshot_count=10000,
        )
        db.add(admin_tenant)
        await db.flush()
        print(f"[+] Admin tenant created: {admin_tenant.id}")

        # --- Demo tenant ---
        demo_tenant = Tenant(
            name="Demo Company",
            slug="demo",
            status="active",
            tier="pro",
            max_concurrent_cells=50,
            max_persistent_storage_gb=100,
            max_snapshot_count=500,
        )
        db.add(demo_tenant)
        await db.flush()
        print(f"[+] Demo tenant created: {demo_tenant.id}")

        # --- Admin user ---
        admin_user = User(
            tenant_id=admin_tenant.id,
            email="admin@aijailer.com",
            name="Admin User",
            role="owner",
            status="active",
        )
        db.add(admin_user)
        await db.flush()

        # --- Demo API key ---
        demo_key = "aj_live_demo_key_for_development_only"
        demo_api_key = ApiKey(
            tenant_id=demo_tenant.id,
            created_by=admin_user.id,
            name="Demo API Key",
            key_hash=hashlib.sha256(demo_key.encode()).hexdigest(),
            key_prefix="aj_live_demo",
            role="admin",
            status="active",
        )
        db.add(demo_api_key)
        await db.flush()
        print(f"[+] Demo API key created: {demo_key}")

        # --- Default security policies ---

        # Level 4: Maximum containment
        policy_max = SecurityPolicy(
            tenant_id=None,  # Platform-wide
            name="maximum-containment",
            description="Level 4: No network, minimal filesystem, minimal syscalls",
            network_policy={
                "default": "deny",
                "egress": [],
            },
            filesystem_policy={
                "writable_paths": ["/tmp"],
                "denied_paths": ["/etc", "/root", "/var", "/usr", "/bin", "/sbin"],
            },
            syscall_policy={
                "blocked": [
                    "mount", "umount2", "ptrace", "kexec_load", "bpf",
                    "keyctl", "add_key", "request_key", "perf_event_open",
                    "unshare", "setns", "clone3",
                ],
            },
            resource_policy={
                "max_vcpus": 1,
                "max_memory_mb": 512,
                "max_disk_mb": 1024,
                "max_pids": 64,
                "max_open_files": 256,
            },
            capability_policy={
                "drop_all": True,
            },
        )
        db.add(policy_max)

        # Level 3: Restricted (default)
        policy_restricted = SecurityPolicy(
            tenant_id=None,
            name="restricted-default",
            description="Level 3: Allowed domains only, limited filesystem, standard syscall filter",
            network_policy={
                "default": "deny",
                "egress": [
                    {
                        "action": "allow",
                        "destinations": [
                            {"domain": "api.openai.com"},
                            {"domain": "api.anthropic.com"},
                            {"domain": "pypi.org"},
                            {"domain": "files.pythonhosted.org"},
                            {"domain": "registry.npmjs.org"},
                        ],
                        "protocols": ["tcp"],
                        "ports": [443],
                    }
                ],
            },
            filesystem_policy={
                "writable_paths": ["/tmp", "/home/agent", "/data"],
                "denied_paths": ["/etc/shadow", "/root"],
            },
            syscall_policy={
                "blocked": ["mount", "ptrace", "kexec_load", "bpf"],
            },
            resource_policy={
                "max_vcpus": 4,
                "max_memory_mb": 4096,
                "max_disk_mb": 10240,
                "max_pids": 256,
                "max_open_files": 1024,
            },
            capability_policy={
                "allowed": ["CAP_NET_BIND_SERVICE"],
            },
        )
        db.add(policy_restricted)

        # Level 2: Standard
        policy_standard = SecurityPolicy(
            tenant_id=None,
            name="standard",
            description="Level 2: Internet access, full filesystem, relaxed syscalls",
            network_policy={
                "default": "allow",
                "egress": [],
            },
            filesystem_policy={
                "writable_paths": ["/"],
                "denied_paths": [],
            },
            syscall_policy={
                "blocked": ["kexec_load", "bpf"],
            },
            resource_policy={
                "max_vcpus": 8,
                "max_memory_mb": 16384,
                "max_disk_mb": 102400,
                "max_pids": 1024,
                "max_open_files": 4096,
            },
            capability_policy={},
        )
        db.add(policy_standard)

        # Level 1: Permissive
        policy_permissive = SecurityPolicy(
            tenant_id=None,
            name="permissive",
            description="Level 1: Full internet, full filesystem, minimal filtering",
            network_policy={"default": "allow"},
            filesystem_policy={"writable_paths": ["/"], "denied_paths": []},
            syscall_policy={"blocked": []},
            resource_policy={
                "max_vcpus": 32,
                "max_memory_mb": 65536,
                "max_disk_mb": 1048576,
                "max_pids": 4096,
                "max_open_files": 65536,
            },
            capability_policy={},
        )
        db.add(policy_permissive)

        await db.flush()
        print("[+] Default security policies created (4 levels)")

        # Set default policy for demo tenant
        demo_tenant.default_security_policy_id = policy_restricted.id
        await db.commit()

        print("\n=== Seed complete ===")
        print(f"Demo API Key: {demo_key}")
        print(f"Demo Tenant ID: {demo_tenant.id}")
        print(f"Default Policy ID: {policy_restricted.id}")


async def main():
    await create_tables()
    await seed_data()
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
