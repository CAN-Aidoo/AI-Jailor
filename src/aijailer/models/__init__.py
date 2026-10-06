"""Import every model so Base.metadata knows all tables."""

from aijailer.models import attack_pattern  # noqa: F401
from aijailer.models import audit  # noqa: F401
from aijailer.models import cell  # noqa: F401
from aijailer.models import certified_component  # noqa: F401
from aijailer.models import constraint  # noqa: F401
from aijailer.models import execution  # noqa: F401
from aijailer.models import generation_log  # noqa: F401
from aijailer.models import node  # noqa: F401
from aijailer.models import policy  # noqa: F401
from aijailer.models import security_certificate  # noqa: F401
from aijailer.models import snapshot  # noqa: F401
from aijailer.models import tenant  # noqa: F401
from aijailer.models import webhook  # noqa: F401
from aijailer.models import tenant_secret  # noqa: F401
