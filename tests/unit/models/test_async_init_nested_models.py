from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, Encrypted, Hashed
from pydantic_encryption.types import EncryptedValue, HashedValue


class TestAsyncInitNestedModels:
    """Test async_init with nested SecureModel fields."""

    @pytest.mark.asyncio
    async def test_async_init_nested_model_encrypts(self):
        """Test that async_init encrypts the fields of a nested model."""

        class _Nested(BaseModel):
            value: Annotated[str, Encrypted]

        class _User(BaseModel):
            name: str
            nested: _Nested

        user = await _User.async_init(name="test name", nested={"value": "first"})

        assert user.name == "test name"
        assert isinstance(user.nested.value, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_hashes(self):
        """Test that async_init hashes the fields of a nested model."""

        class _Credentials(BaseModel):
            password: Annotated[str, Hashed]

        class _User(BaseModel):
            name: str
            credentials: _Credentials

        user = await _User.async_init(name="test name", credentials={"password": "secret123"})

        assert user.name == "test name"
        assert isinstance(user.credentials.password, HashedValue)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_mixed(self):
        """Test that async_init processes the parent's and the nested model's fields."""

        class _Nested(BaseModel):
            value: Annotated[str, Encrypted]

        class _User(BaseModel):
            email: Annotated[str, Encrypted]
            nested: _Nested

        user = await _User.async_init(email="test@example.com", nested={"value": "first"})

        assert isinstance(user.email, EncryptedValue)
        assert isinstance(user.nested.value, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_pre_constructed_nested_model(self):
        """Test that a nested model encrypted before async_init stays valid."""

        class _Nested(BaseModel):
            value: Annotated[str, Encrypted]

        class _User(BaseModel):
            name: str
            nested: _Nested

        nested = _Nested(value="first")  # sync crypto already ran
        assert isinstance(nested.value, EncryptedValue)

        user = await _User.async_init(name="test name", nested=nested)

        assert user.name == "test name"
        assert isinstance(user.nested.value, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_in_list(self):
        """Test that async_init processes models inside a list."""

        class _Nested(BaseModel):
            value: Annotated[str, Encrypted]

        class _User(BaseModel):
            name: str
            nested: list[_Nested]

        user = await _User.async_init(
            name="test name",
            nested=[{"value": "first"}, {"value": "second"}],
        )

        assert user.name == "test name"
        assert isinstance(user.nested[0].value, EncryptedValue)
        assert isinstance(user.nested[1].value, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_in_dict(self):
        """Test that async_init processes models inside a dict."""

        class _Nested(BaseModel):
            value: Annotated[str, Encrypted]

        class _User(BaseModel):
            name: str
            nested: dict[str, _Nested]

        user = await _User.async_init(
            name="test name",
            nested={"first": {"value": "one"}, "second": {"value": "two"}},
        )

        assert user.name == "test name"
        assert isinstance(user.nested["first"].value, EncryptedValue)
        assert isinstance(user.nested["second"].value, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_in_nested_list(self):
        """Test that async_init processes models inside nested lists."""

        class _Nested(BaseModel):
            value: Annotated[str, Encrypted]

        class _User(BaseModel):
            name: str
            nested_groups: list[list[_Nested]]

        user = await _User.async_init(
            name="test name",
            nested_groups=[
                [{"value": "one"}],
                [{"value": "two"}, {"value": "three"}],
            ],
        )

        assert user.name == "test name"
        assert isinstance(user.nested_groups[0][0].value, EncryptedValue)
        assert isinstance(user.nested_groups[1][0].value, EncryptedValue)
        assert isinstance(user.nested_groups[1][1].value, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_in_dict_of_lists(self):
        """Test that async_init processes models inside lists held by a dict."""

        class _Nested(BaseModel):
            value: Annotated[str, Encrypted]

        class _User(BaseModel):
            name: str
            nested: dict[str, list[_Nested]]

        user = await _User.async_init(
            name="test name",
            nested={
                "first": [{"value": "one"}, {"value": "two"}],
                "second": [{"value": "three"}],
            },
        )

        assert user.name == "test name"
        assert isinstance(user.nested["first"][0].value, EncryptedValue)
        assert isinstance(user.nested["first"][1].value, EncryptedValue)
        assert isinstance(user.nested["second"][0].value, EncryptedValue)
