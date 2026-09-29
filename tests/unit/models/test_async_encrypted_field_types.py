from datetime import date
from decimal import Decimal
from typing import Annotated
from uuid import UUID, uuid4

import pytest

from pydantic_encryption import BaseModel, Encrypted
from pydantic_encryption.types import EncryptedValue


class TestAsyncEncryptedFieldTypes:
    """Test that an encrypted field returns the type it declares on the async path."""

    @pytest.mark.asyncio
    async def test_async_round_trip_preserves_the_declared_type(self):
        """Test that async encryption round trips every value type a field can declare."""

        class _Model(BaseModel):
            dob: Annotated[date, Encrypted]
            amount: Annotated[Decimal, Encrypted]
            external_id: Annotated[UUID, Encrypted]

        values = {"dob": date(1990, 5, 4), "amount": Decimal("12.34"), "external_id": uuid4()}
        model = await _Model.async_init(**values)

        assert all(isinstance(getattr(model, name), EncryptedValue) for name in values)

        await model.async_decrypt_data()

        assert model.dob == values["dob"]
        assert model.amount == values["amount"]
        assert model.external_id == values["external_id"]
