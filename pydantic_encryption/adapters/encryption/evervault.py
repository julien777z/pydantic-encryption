from typing import Any, ClassVar

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("evervault", "evervault")

import evervault

from pydantic_encryption.config import settings

EvervaultData = dict[str, (bytes | list | dict | set | str)]


class EvervaultAdapter:
    """Adapter for Evervault encryption."""

    _client: ClassVar[Any | None] = None

    @classmethod
    def _get_client(cls) -> Any:
        if cls._client is None:
            if not (
                settings.EVERVAULT_APP_ID
                and settings.EVERVAULT_API_KEY
                and settings.EVERVAULT_ENCRYPTION_ROLE
            ):
                raise ValueError(
                    "Evervault requires EVERVAULT_APP_ID, EVERVAULT_API_KEY, "
                    "and EVERVAULT_ENCRYPTION_ROLE to be set."
                )

            cls._client = evervault.Client(
                app_uuid=settings.EVERVAULT_APP_ID, api_key=settings.EVERVAULT_API_KEY
            )

        return cls._client

    @classmethod
    def encrypt(cls, fields: dict[str, str]) -> EvervaultData:
        client = cls._get_client()

        return client.encrypt(fields, role=settings.EVERVAULT_ENCRYPTION_ROLE)

    @classmethod
    def decrypt(cls, fields: EvervaultData) -> EvervaultData:
        client = cls._get_client()

        return client.decrypt(fields)
