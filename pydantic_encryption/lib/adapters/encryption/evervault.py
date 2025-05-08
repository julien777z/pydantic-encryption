from pydantic_encryption.config import settings
from pydantic_encryption.annotations import EncryptionMethod

try:
    import evervault
except ImportError:
    evervault = None
else:
    EVERVAULT_CLIENT = None

    EvervaultData = dict[str, (bytes | list | dict | set | str)]


if settings.ENCRYPTION_METHOD == EncryptionMethod.EVERVAULT:
    if not (
        settings.EVERVAULT_APP_ID
        and settings.EVERVAULT_API_KEY
        and settings.EVERVAULT_ENCRYPTION_ROLE
    ):
        raise ValueError(
            "Evervault settings are not configured. Please set the following environment variables: EVERVAULT_APP_ID, EVERVAULT_API_KEY, EVERVAULT_ENCRYPTION_ROLE."
        )

    if not evervault:
        raise ValueError(
            "Evervault is not available. Please install this package with the `evervault` extra."
        )

    EVERVAULT_CLIENT = evervault.Client(
        app_uuid=settings.EVERVAULT_APP_ID, api_key=settings.EVERVAULT_API_KEY
    )


def evervault_encrypt(
    fields: dict[str, str],
) -> EvervaultData:
    """Encrypt data using Evervault."""

    return EVERVAULT_CLIENT.encrypt(fields, role=settings.EVERVAULT_ENCRYPTION_ROLE)


def evervault_decrypt(
    fields: EvervaultData,
) -> EvervaultData:
    """Decrypt data using Evervault."""

    return EVERVAULT_CLIENT.decrypt(fields)
