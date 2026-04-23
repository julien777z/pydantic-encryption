import pytest
from typing import Annotated

from pydantic_encryption import BaseModel, Encrypted, Hashed
from pydantic_encryption.config import settings
from pydantic_encryption.models.base import _defer_crypto_to_async
from pydantic_encryption.types import (
    BlindIndex,
    BlindIndexMethod,
    BlindIndexValue,
    EncryptedValue,
    HashedValue,
)


def _construct_without_crypto(cls, **data):
    """Construct a model instance skipping sync crypto (for testing async methods individually)."""
    token = _defer_crypto_to_async.set(True)
    try:
        return cls(**data)
    finally:
        _defer_crypto_to_async.reset(token)


class TestAsyncInit:
    """Test BaseModel.async_init produces same results as sync construction."""

    @pytest.mark.asyncio
    async def test_async_init_encrypts_fields(self):
        class _Model(BaseModel):
            secret: Annotated[bytes, Encrypted]

        model = await _Model.async_init(secret="plaintext")

        assert isinstance(model.secret, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_hashes_fields(self):
        class _Model(BaseModel):
            password: Annotated[str, Hashed]

        model = await _Model.async_init(password="secret123")

        assert isinstance(model.password, HashedValue)

    @pytest.mark.asyncio
    async def test_async_init_mixed_encrypt_and_hash(self):
        class _Model(BaseModel):
            username: str
            email: Annotated[bytes, Encrypted]
            password: Annotated[str, Hashed]

        model = await _Model.async_init(username="john", email="john@example.com", password="secret123")

        assert model.username == "john"
        assert isinstance(model.email, EncryptedValue)
        assert isinstance(model.password, HashedValue)

    @pytest.mark.asyncio
    async def test_async_init_multiple_encrypted_fields(self):
        class _Model(BaseModel):
            field1: Annotated[bytes, Encrypted]
            field2: Annotated[bytes, Encrypted]
            field3: Annotated[bytes, Encrypted]

        model = await _Model.async_init(field1="secret1", field2="secret2", field3="secret3")

        assert isinstance(model.field1, EncryptedValue)
        assert isinstance(model.field2, EncryptedValue)
        assert isinstance(model.field3, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_optional_encrypted_field_with_value(self):
        class _Model(BaseModel):
            secret: Annotated[bytes, Encrypted] | None = None

        model = await _Model.async_init(secret="my secret")

        assert isinstance(model.secret, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_optional_encrypted_field_none(self):
        class _Model(BaseModel):
            secret: Annotated[bytes, Encrypted] | None = None

        model = await _Model.async_init()

        assert model.secret is None

    @pytest.mark.asyncio
    async def test_async_init_decryptable(self):
        """async_init encrypted values can be decrypted with async_decrypt_data."""

        class _Model(BaseModel):
            data: Annotated[bytes, Encrypted]

        original = "secret data"
        model = await _Model.async_init(data=original)

        assert isinstance(model.data, EncryptedValue)

        await model.async_decrypt_data()
        assert model.data == original

    @pytest.mark.asyncio
    async def test_async_init_pydantic_validation_still_runs(self):
        """Pydantic validation is not skipped by async_init."""

        class _Model(BaseModel):
            age: int
            secret: Annotated[bytes, Encrypted]

        with pytest.raises(Exception):
            await _Model.async_init(age="not_a_number", secret="test")

    @pytest.mark.asyncio
    async def test_async_init_sync_still_works_after(self):
        """Sync construction still works after async_init has been used."""

        class _Model(BaseModel):
            secret: Annotated[bytes, Encrypted]

        async_model = await _Model.async_init(secret="async_secret")
        sync_model = _Model(secret="sync_secret")

        assert isinstance(async_model.secret, EncryptedValue)
        assert isinstance(sync_model.secret, EncryptedValue)


class TestAsyncEncryptData:
    """Test async_encrypt_data method."""

    @pytest.mark.asyncio
    async def test_async_encrypt_data(self):
        class _Model(BaseModel):
            secret: Annotated[bytes, Encrypted]

        model = _construct_without_crypto(_Model, secret="plaintext")
        assert not isinstance(model.secret, EncryptedValue)

        await model.async_encrypt_data()
        assert isinstance(model.secret, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_encrypt_data_multiple_fields(self):
        class _Model(BaseModel):
            field1: Annotated[bytes, Encrypted]
            field2: Annotated[bytes, Encrypted]

        model = _construct_without_crypto(_Model, field1="secret1", field2="secret2")
        await model.async_encrypt_data()

        assert isinstance(model.field1, EncryptedValue)
        assert isinstance(model.field2, EncryptedValue)


class TestAsyncDecryptData:
    """Test async_decrypt_data method."""

    @pytest.mark.asyncio
    async def test_async_decrypt_data(self):
        class _Model(BaseModel):
            data: Annotated[bytes, Encrypted]

        model = _Model(data="secret data")
        await model.async_decrypt_data()
        assert model.data == "secret data"

    @pytest.mark.asyncio
    async def test_async_decrypt_data_multiple(self):
        class _Model(BaseModel):
            data1: Annotated[bytes, Encrypted]
            data2: Annotated[bytes, Encrypted]

        model = _Model(data1="secret1", data2="secret2")
        await model.async_decrypt_data()

        assert model.data1 == "secret1"
        assert model.data2 == "secret2"

    @pytest.mark.asyncio
    async def test_async_decrypt_data_returns_self(self):
        class _Model(BaseModel):
            data: Annotated[bytes, Encrypted]

        model = _Model(data="secret")
        result = await model.async_decrypt_data()
        assert result is model


class TestAsyncHashData:
    """Test async_hash_data method."""

    @pytest.mark.asyncio
    async def test_async_hash_data(self):
        class _Model(BaseModel):
            password: Annotated[str, Hashed]

        model = _construct_without_crypto(_Model, password="secret123")
        assert not isinstance(model.password, HashedValue)

        await model.async_hash_data()
        assert isinstance(model.password, HashedValue)

    @pytest.mark.asyncio
    async def test_async_hash_data_multiple_fields(self):
        class _Model(BaseModel):
            password1: Annotated[str, Hashed]
            password2: Annotated[str, Hashed]

        model = _construct_without_crypto(_Model, password1="secret1", password2="secret2")
        await model.async_hash_data()

        assert isinstance(model.password1, HashedValue)
        assert isinstance(model.password2, HashedValue)


class TestAsyncPostInit:
    """Test async_post_init method."""

    @pytest.mark.asyncio
    async def test_async_post_init_encrypt_and_hash(self):
        class _Model(BaseModel):
            email: Annotated[bytes, Encrypted]
            password: Annotated[str, Hashed]

        model = _construct_without_crypto(_Model, email="user@example.com", password="secret123")
        assert not isinstance(model.email, EncryptedValue)
        assert not isinstance(model.password, HashedValue)

        await model.async_post_init()

        assert isinstance(model.email, EncryptedValue)
        assert isinstance(model.password, HashedValue)

    @pytest.mark.asyncio
    async def test_async_post_init_then_decrypt(self):
        """async_post_init encrypts, then async_decrypt_data decrypts."""

        class _Model(BaseModel):
            data: Annotated[bytes, Encrypted]

        model = _construct_without_crypto(_Model, data="secret")
        await model.async_post_init()
        assert isinstance(model.data, EncryptedValue)

        await model.async_decrypt_data()
        assert model.data == "secret"


class TestAsyncInitNestedModels:
    """Test async_init with nested SecureModel fields."""

    @pytest.mark.asyncio
    async def test_async_init_nested_model_encrypts(self):
        """Nested SecureModel fields have their crypto processed during async_init."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypted]

        class _User(BaseModel):
            name: str
            address: _Address

        user = await _User.async_init(name="John", address={"street": "123 Main St"})

        assert user.name == "John"
        assert isinstance(user.address.street, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_hashes(self):
        """Nested SecureModel fields with Hashed annotations are processed."""

        class _Credentials(BaseModel):
            password: Annotated[str, Hashed]

        class _User(BaseModel):
            name: str
            credentials: _Credentials

        user = await _User.async_init(name="John", credentials={"password": "secret123"})

        assert user.name == "John"
        assert isinstance(user.credentials.password, HashedValue)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_mixed(self):
        """Parent and nested models both have crypto fields processed."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypted]

        class _User(BaseModel):
            email: Annotated[bytes, Encrypted]
            address: _Address

        user = await _User.async_init(email="john@example.com", address={"street": "123 Main St"})

        assert isinstance(user.email, EncryptedValue)
        assert isinstance(user.address.street, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_pre_constructed_nested_model(self):
        """Pre-constructed nested models (already encrypted) remain valid."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypted]

        class _User(BaseModel):
            name: str
            address: _Address

        address = _Address(street="123 Main St")  # sync crypto already ran
        assert isinstance(address.street, EncryptedValue)

        user = await _User.async_init(name="John", address=address)

        assert user.name == "John"
        assert isinstance(user.address.street, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_in_list(self):
        """SecureModel instances inside a list are recursively processed."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypted]

        class _User(BaseModel):
            name: str
            addresses: list[_Address]

        user = await _User.async_init(
            name="John",
            addresses=[{"street": "123 Main St"}, {"street": "456 Oak Ave"}],
        )

        assert user.name == "John"
        assert isinstance(user.addresses[0].street, EncryptedValue)
        assert isinstance(user.addresses[1].street, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_in_dict(self):
        """SecureModel instances inside a dict are recursively processed."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypted]

        class _User(BaseModel):
            name: str
            addresses: dict[str, _Address]

        user = await _User.async_init(
            name="John",
            addresses={"home": {"street": "123 Main St"}, "work": {"street": "456 Oak Ave"}},
        )

        assert user.name == "John"
        assert isinstance(user.addresses["home"].street, EncryptedValue)
        assert isinstance(user.addresses["work"].street, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_in_nested_list(self):
        """SecureModel instances inside nested lists are recursively processed."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypted]

        class _User(BaseModel):
            name: str
            address_groups: list[list[_Address]]

        user = await _User.async_init(
            name="John",
            address_groups=[[{"street": "123 Main St"}], [{"street": "456 Oak Ave"}, {"street": "789 Elm St"}]],
        )

        assert user.name == "John"
        assert isinstance(user.address_groups[0][0].street, EncryptedValue)
        assert isinstance(user.address_groups[1][0].street, EncryptedValue)
        assert isinstance(user.address_groups[1][1].street, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_in_dict_of_lists(self):
        """SecureModel instances inside dict values that are lists are recursively processed."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypted]

        class _User(BaseModel):
            name: str
            addresses: dict[str, list[_Address]]

        user = await _User.async_init(
            name="John",
            addresses={
                "home": [{"street": "123 Main St"}, {"street": "456 Oak Ave"}],
                "work": [{"street": "789 Elm St"}],
            },
        )

        assert user.name == "John"
        assert isinstance(user.addresses["home"][0].street, EncryptedValue)
        assert isinstance(user.addresses["home"][1].street, EncryptedValue)
        assert isinstance(user.addresses["work"][0].street, EncryptedValue)


@pytest.fixture(autouse=True)
def set_blind_index_key(monkeypatch):
    monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", "test-secret-key-for-async")


class TestAsyncBlindIndexData:
    """Test async_blind_index_data method."""

    @pytest.mark.asyncio
    async def test_async_blind_index_hmac_sha256(self):
        class _Model(BaseModel):
            email: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        model = _construct_without_crypto(_Model, email="test@example.com")
        assert not isinstance(model.email, BlindIndexValue)

        await model.async_blind_index_data()
        assert isinstance(model.email, BlindIndexValue)

    @pytest.mark.asyncio
    async def test_async_blind_index_argon2(self):
        class _Model(BaseModel):
            email: Annotated[bytes, BlindIndex(BlindIndexMethod.ARGON2)]

        model = _construct_without_crypto(_Model, email="test@example.com")

        await model.async_blind_index_data()
        assert isinstance(model.email, BlindIndexValue)

    @pytest.mark.asyncio
    async def test_async_blind_index_multiple_fields(self):
        class _Model(BaseModel):
            email: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]
            phone: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        model = _construct_without_crypto(_Model, email="test@example.com", phone="1234567890")
        await model.async_blind_index_data()

        assert isinstance(model.email, BlindIndexValue)
        assert isinstance(model.phone, BlindIndexValue)

    @pytest.mark.asyncio
    async def test_async_blind_index_deterministic(self):
        """Async blind index produces same result as sync."""

        class _SyncModel(BaseModel):
            email: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        class _AsyncModel(BaseModel):
            email: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        sync_model = _SyncModel(email="test@example.com")
        async_model = await _AsyncModel.async_init(email="test@example.com")

        assert sync_model.email == async_model.email

    @pytest.mark.asyncio
    async def test_async_blind_index_missing_key_raises(self, monkeypatch):
        class _Model(BaseModel):
            email: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        model = _construct_without_crypto(_Model, email="test@example.com")
        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", None)

        with pytest.raises(ValueError, match="BLIND_INDEX_SECRET_KEY must be set"):
            await model.async_blind_index_data()

    @pytest.mark.asyncio
    async def test_async_blind_index_optional_none_no_key_succeeds(self, monkeypatch):
        """Optional blind index fields with None value succeed even without key configured."""

        class _Model(BaseModel):
            email: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)] | None = None

        model = _construct_without_crypto(_Model)
        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", None)

        # Should not raise — matches sync behavior
        await model.async_blind_index_data()
        assert model.email is None


class TestAsyncEncryptDataErrors:
    """Test error branches in async encrypt/decrypt methods."""

    @pytest.mark.asyncio
    async def test_async_encrypt_data_missing_method_raises(self, monkeypatch):
        class _Model(BaseModel):
            secret: Annotated[bytes, Encrypted]

        model = _construct_without_crypto(_Model, secret="plaintext")
        monkeypatch.setattr(settings, "ENCRYPTION_METHOD", None)

        with pytest.raises(ValueError, match="ENCRYPTION_METHOD must be set"):
            await model.async_encrypt_data()

    @pytest.mark.asyncio
    async def test_async_decrypt_data_missing_method_raises(self, monkeypatch):
        class _Model(BaseModel):
            data: Annotated[bytes, Encrypted]

        model = _Model(data="secret")
        monkeypatch.setattr(settings, "ENCRYPTION_METHOD", None)

        with pytest.raises(ValueError, match="ENCRYPTION_METHOD must be set"):
            await model.async_decrypt_data()

    @pytest.mark.asyncio
    async def test_async_encrypt_no_pending_fields_is_noop(self):
        class _Model(BaseModel):
            name: str

        model = _construct_without_crypto(_Model, name="john")
        await model.async_encrypt_data()
        assert model.name == "john"

    @pytest.mark.asyncio
    async def test_async_decrypt_no_pending_fields_is_noop(self):
        class _Model(BaseModel):
            name: str

        model = _construct_without_crypto(_Model, name="john")
        result = await model.async_decrypt_data()
        assert model.name == "john"
        assert result is model

    @pytest.mark.asyncio
    async def test_async_hash_no_pending_fields_is_noop(self):
        class _Model(BaseModel):
            name: str

        model = _construct_without_crypto(_Model, name="john")
        await model.async_hash_data()
        assert model.name == "john"

    @pytest.mark.asyncio
    async def test_async_blind_index_no_pending_fields_is_noop(self):
        class _Model(BaseModel):
            name: str

        model = _construct_without_crypto(_Model, name="john")
        await model.async_blind_index_data()
        assert model.name == "john"
