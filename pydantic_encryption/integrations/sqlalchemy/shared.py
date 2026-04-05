import base64
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Final
from uuid import UUID

# Type alias for all supported encrypted value types
EncryptableValue = str | bytes | bool | int | float | Decimal | UUID | date | datetime | time | timedelta

VERSION_PREFIX: Final[str] = "v1"


class TypePrefix(StrEnum):
    """Type prefixes for auto-detection of encrypted field types."""

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
