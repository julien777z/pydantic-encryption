import subprocess
import sys
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Annotated
from uuid import uuid4

import pytest

from pydantic_encryption import BaseModel, Encrypted
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue
from tests.unit.models.utils import NO_SQLALCHEMY_SCRIPT


class TestEncryptedFieldTypes:
    """Test that an encrypted field returns the type it declares."""

    @pytest.mark.parametrize(
        "value",
        [
            "secret data",
            b"secret bytes",
            True,
            42,
            3.5,
            Decimal("12.34"),
            uuid4(),
            date(1990, 5, 4),
            datetime(2026, 1, 2, 3, 4, 5),
            time(13, 30),
            timedelta(days=2, seconds=3),
        ],
        ids=[
            "str",
            "bytes",
            "bool",
            "int",
            "float",
            "decimal",
            "uuid",
            "date",
            "datetime",
            "time",
            "timedelta",
        ],
    )
    def test_round_trip_preserves_type(self, value: object):
        """Test that every type an encrypted column accepts survives a model round trip too."""

        class _Model(BaseModel):
            data: Annotated[object, Encrypted]

        model = _Model(data=value)

        assert isinstance(model.data, EncryptedValue)

        model.decrypt_data()

        assert model.data == value
        assert type(model.data) is type(value)

    def test_model_encryption_runs_without_the_sqlalchemy_extra(self):
        """Test that encrypting a model field needs nothing from the SQLAlchemy integration."""

        environment = {
            "ENCRYPTION_METHOD": "fernet",
            "ENCRYPTION_KEY": settings.ENCRYPTION_KEY or "",
            "PATH": "/usr/bin:/bin",
        }

        result = subprocess.run(
            [sys.executable, "-c", NO_SQLALCHEMY_SCRIPT],
            capture_output=True,
            text=True,
            env=environment,
        )

        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("value", [["secret"], {"secret": 1}], ids=["list", "dict"])
    def test_unsupported_type_refused(self, value: object):
        """Test that a value of a type no encrypted value holds is refused instead of stored as its repr."""

        class _Model(BaseModel):
            data: Annotated[object, Encrypted]

        with pytest.raises(TypeError, match=repr(type(value).__name__)):
            _Model(data=value)
