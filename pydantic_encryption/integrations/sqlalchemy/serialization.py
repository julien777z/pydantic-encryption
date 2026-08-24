import base64
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Final
from uuid import UUID

from pydantic_encryption.types import FieldBinding, FieldBindingError

EncryptableValue = str | bytes | bool | int | float | Decimal | UUID | date | datetime | time | timedelta

VERSION_PREFIX: Final[str] = "v2"

#: What an unbound envelope stores where a bound one stores its table and column.
UNBOUND_IDENTITY: Final[str] = ""


def binding_identity(binding: FieldBinding | None) -> str:
    """Return the identity an envelope carries for this binding, or the unbound marker."""

    return binding.identity if binding is not None else UNBOUND_IDENTITY


class TypePrefix(StrEnum):
    """Type prefixes for auto-detecting encrypted field types on decode."""

    STR = "str"
    BYTES = "bytes"
    BOOL = "bool"
    INT = "int"
    FLOAT = "float"
    DECIMAL = "decimal"
    UUID = "uuid"
    DATE = "date"
    DATETIME = "datetime"
    TIME = "time"
    TIMEDELTA = "timedelta"


def encode_value(value: EncryptableValue, binding: FieldBinding | None) -> str:
    """Serialize a Python value to a ``version:binding:type:data`` string for encryption."""

    match value:
        case datetime():
            type_data = f"{TypePrefix.DATETIME}:{value.isoformat()}"
        case date():
            type_data = f"{TypePrefix.DATE}:{value.isoformat()}"
        case time():
            type_data = f"{TypePrefix.TIME}:{value.isoformat()}"
        case timedelta():
            type_data = f"{TypePrefix.TIMEDELTA}:{value.days},{value.seconds},{value.microseconds}"
        case bytes():
            type_data = f"{TypePrefix.BYTES}:{base64.b64encode(value).decode('ascii')}"
        case bool():
            type_data = f"{TypePrefix.BOOL}:{str(value).lower()}"
        case int():
            type_data = f"{TypePrefix.INT}:{value}"
        case float():
            type_data = f"{TypePrefix.FLOAT}:{value!r}"
        case Decimal():
            type_data = f"{TypePrefix.DECIMAL}:{value}"
        case UUID():
            type_data = f"{TypePrefix.UUID}:{value}"
        case _:
            type_data = f"{TypePrefix.STR}:{value}"

    return f"{VERSION_PREFIX}:{binding_identity(binding)}:{type_data}"


def decode_value(value: str, binding: FieldBinding | None) -> EncryptableValue:
    """Deserialize a decrypted envelope, refusing one written for a different field."""

    version, _, remainder = value.partition(":")
    if not version:
        return value

    if version != VERSION_PREFIX:
        raise RuntimeError("Unknown version")

    stored_identity, _, type_data = remainder.partition(":")
    expected_identity = binding_identity(binding)

    if stored_identity != expected_identity:
        raise FieldBindingError(
            f"Ciphertext is bound to {stored_identity or 'no field'} "
            f"but was read as {expected_identity or 'no field'}."
        )

    type_prefix, _, data = type_data.partition(":")

    match type_prefix:
        case TypePrefix.DATETIME:
            return datetime.fromisoformat(data)
        case TypePrefix.DATE:
            return date.fromisoformat(data)
        case TypePrefix.TIME:
            return time.fromisoformat(data)
        case TypePrefix.TIMEDELTA:
            parts = data.split(",")
            return timedelta(days=int(parts[0]), seconds=int(parts[1]), microseconds=int(parts[2]))
        case TypePrefix.BYTES:
            return base64.b64decode(data)
        case TypePrefix.BOOL:
            return data == "true"
        case TypePrefix.INT:
            return int(data)
        case TypePrefix.FLOAT:
            return float(data)
        case TypePrefix.DECIMAL:
            return Decimal(data)
        case TypePrefix.UUID:
            return UUID(data)
        case TypePrefix.STR:
            return data
        case _:
            return data
