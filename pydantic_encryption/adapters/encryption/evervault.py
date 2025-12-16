from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("evervault", "evervault")

import evervault

from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptionMethod

EVERVAULT_CLIENT = None

EvervaultData = dict[str, (bytes | list | dict | set | str)]


def _ensure_client() -> None:
    """Initialize Evervault client lazily and validate configuration."""

    global EVERVAULT_CLIENT

    if settings.ENCRYPTION_METHOD != EncryptionMethod.EVERVAULT:
        return

    if not (settings.EVERVAULT_APP_ID and settings.EVERVAULT_API_KEY and settings.EVERVAULT_ENCRYPTION_ROLE):
        raise ValueError(
            "Evervault settings are not configured. Please set the following environment variables: "
            "EVERVAULT_APP_ID, EVERVAULT_API_KEY, EVERVAULT_ENCRYPTION_ROLE."
        )

    if EVERVAULT_CLIENT is None:
        EVERVAULT_CLIENT = evervault.Client(
            app_uuid=settings.EVERVAULT_APP_ID, api_key=settings.EVERVAULT_API_KEY
        )


def evervault_encrypt(fields: dict[str, str]) -> EvervaultData:
    """Encrypt data using Evervault."""

    _ensure_client()

    return EVERVAULT_CLIENT.encrypt(fields, role=settings.EVERVAULT_ENCRYPTION_ROLE)


def evervault_decrypt(fields: EvervaultData) -> EvervaultData:
    """Decrypt data using Evervault."""

    _ensure_client()

    return EVERVAULT_CLIENT.decrypt(fields)
