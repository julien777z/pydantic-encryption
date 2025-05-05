from pydantic_encryption.config import settings

try:
    import evervault
except ImportError:
    evervault = None

EVERVAULT_CLIENT = None

EvervaultData = dict[str, (bytes | list | dict | set | str)]


def load_evervault_client():
    """Load the Evervault encryption client."""

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

    global EVERVAULT_CLIENT

    EVERVAULT_CLIENT = EVERVAULT_CLIENT or evervault.Client(
        app_uuid=settings.EVERVAULT_APP_ID, api_key=settings.EVERVAULT_API_KEY
    )

    return EVERVAULT_CLIENT


def evervault_encrypt(
    fields: dict[str, str],
) -> EvervaultData:
    """Encrypt data using Evervault."""

    evervault_client = load_evervault_client()

    return evervault_client.encrypt(fields, role=settings.EVERVAULT_ENCRYPTION_ROLE)


def evervault_decrypt(
    fields: EvervaultData,
) -> EvervaultData:
    """Decrypt data using Evervault."""

    evervault_client = load_evervault_client()

    return evervault_client.decrypt(fields)
