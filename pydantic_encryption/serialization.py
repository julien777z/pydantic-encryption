import base64
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Final
from uuid import UUID

EncryptableValue = str | bytes | bool | int | float | Decimal | UUID | date | datetime | time | timedelta

VERSION_PREFIX: Final[str] = "v1"


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


def require_encryptable(value: object) -> EncryptableValue:
    """Return the value as one an encrypted cell can hold, refusing any other type."""

    if not isinstance(value, EncryptableValue):
        raise TypeError(f"An encrypted value cannot hold type {type(value).__name__!r}.")

    return value


def encode_value(value: object) -> str:
    """Serialize a Python value to a ``version:type:data`` string for encryption."""

    encryptable = require_encryptable(value)

    match encryptable:
        case datetime():
            type_data = f"{TypePrefix.DATETIME}:{encryptable.isoformat()}"
        case date():
            type_data = f"{TypePrefix.DATE}:{encryptable.isoformat()}"
        case time():
            type_data = f"{TypePrefix.TIME}:{encryptable.isoformat()}"
        case timedelta():
            type_data = (
                f"{TypePrefix.TIMEDELTA}:{encryptable.days},{encryptable.seconds},{encryptable.microseconds}"
            )
        case bytes():
            type_data = f"{TypePrefix.BYTES}:{base64.b64encode(encryptable).decode('ascii')}"
        case bool():
            type_data = f"{TypePrefix.BOOL}:{str(encryptable).lower()}"
        case int():
            type_data = f"{TypePrefix.INT}:{encryptable}"
        case float():
            type_data = f"{TypePrefix.FLOAT}:{encryptable!r}"
        case Decimal():
            type_data = f"{TypePrefix.DECIMAL}:{encryptable}"
        case UUID():
            type_data = f"{TypePrefix.UUID}:{encryptable}"
        case str():
            type_data = f"{TypePrefix.STR}:{encryptable}"

    return f"{VERSION_PREFIX}:{type_data}"


def decode_value(value: str) -> EncryptableValue:
    """Deserialize a decrypted ``version:type:data`` string back to its Python value."""

    version, _, remainder = value.partition(":")
    if not version:
        return value

    if version != VERSION_PREFIX:
        raise RuntimeError("Unknown version")

    type_prefix, _, data = remainder.partition(":")

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
