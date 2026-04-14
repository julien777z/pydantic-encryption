import pytest
from typing import Annotated

from pydantic_encryption import BaseModel, Decrypt, Encrypt, Hash
from pydantic_encryption.config import settings
from pydantic_encryption.models.base import _skip_sync_crypto
from pydantic_encryption.types import BlindIndex, BlindIndexMethod


def _construct_without_crypto(cls, **data):
    """Construct a model instance skipping sync crypto (for testing async methods individually)."""
    token = _skip_sync_crypto.set(True)
    try:
        return cls(**data)
    finally:
        _skip_sync_crypto.reset(token)


class TestAsyncInit:
    """Test BaseModel.async_init produces same results as sync construction."""

    @pytest.mark.asyncio
    async def test_async_init_encrypts_fields(self):
        class _Model(BaseModel):
            secret: Annotated[bytes, Encrypt]

        model = await _Model.async_init(secret="plaintext")

        assert getattr(model.secret, "encrypted", False)

    @pytest.mark.asyncio
    async def test_async_init_hashes_fields(self):
        class _Model(BaseModel):
            password: Annotated[str, Hash]

        model = await _Model.async_init(password="secret123")

        assert getattr(model.password, "hashed", False)

    @pytest.mark.asyncio
    async def test_async_init_mixed_encrypt_and_hash(self):
        class _Model(BaseModel):
            username: str
            email: Annotated[bytes, Encrypt]
            password: Annotated[str, Hash]

        model = await _Model.async_init(username="john", email="john@example.com", password="secret123")

        assert model.username == "john"
        assert getattr(model.email, "encrypted", False)
        assert getattr(model.password, "hashed", False)

    @pytest.mark.asyncio
    async def test_async_init_multiple_encrypted_fields(self):
        class _Model(BaseModel):
            field1: Annotated[bytes, Encrypt]
            field2: Annotated[bytes, Encrypt]
            field3: Annotated[bytes, Encrypt]

        model = await _Model.async_init(field1="secret1", field2="secret2", field3="secret3")

        assert getattr(model.field1, "encrypted", False)
        assert getattr(model.field2, "encrypted", False)
        assert getattr(model.field3, "encrypted", False)

    @pytest.mark.asyncio
    async def test_async_init_optional_encrypted_field_with_value(self):
        class _Model(BaseModel):
            secret: Annotated[bytes, Encrypt] | None = None

        model = await _Model.async_init(secret="my secret")

        assert getattr(model.secret, "encrypted", False)

    @pytest.mark.asyncio
    async def test_async_init_optional_encrypted_field_none(self):
        class _Model(BaseModel):
            secret: Annotated[bytes, Encrypt] | None = None

        model = await _Model.async_init()

        assert model.secret is None

    @pytest.mark.asyncio
    async def test_async_init_decryptable(self):
        """async_init encrypted values can be decrypted."""

        class _EncryptModel(BaseModel):
            data: Annotated[bytes, Encrypt]

        class _DecryptModel(BaseModel):
            data: Annotated[bytes, Decrypt]

        original = "secret data"
        encrypted = await _EncryptModel.async_init(data=original)
        decrypted = _DecryptModel(**encrypted.model_dump())

        assert decrypted.data == original

    @pytest.mark.asyncio
    async def test_async_init_pydantic_validation_still_runs(self):
        """Pydantic validation is not skipped by async_init."""

        class _Model(BaseModel):
            age: int
            secret: Annotated[bytes, Encrypt]

        with pytest.raises(Exception):
            await _Model.async_init(age="not_a_number", secret="test")

    @pytest.mark.asyncio
    async def test_async_init_sync_still_works_after(self):
        """Sync construction still works after async_init has been used."""

        class _Model(BaseModel):
            secret: Annotated[bytes, Encrypt]

        async_model = await _Model.async_init(secret="async_secret")
        sync_model = _Model(secret="sync_secret")

        assert getattr(async_model.secret, "encrypted", False)
        assert getattr(sync_model.secret, "encrypted", False)


class TestAsyncEncryptData:
    """Test async_encrypt_data method."""

    @pytest.mark.asyncio
    async def test_async_encrypt_data(self):
        class _Model(BaseModel):
            secret: Annotated[bytes, Encrypt]

        model = _construct_without_crypto(_Model, secret="plaintext")
        assert not getattr(model.secret, "encrypted", False)

        await model.async_encrypt_data()
        assert getattr(model.secret, "encrypted", False)

    @pytest.mark.asyncio
    async def test_async_encrypt_data_multiple_fields(self):
        class _Model(BaseModel):
            field1: Annotated[bytes, Encrypt]
            field2: Annotated[bytes, Encrypt]

        model = _construct_without_crypto(_Model, field1="secret1", field2="secret2")
        await model.async_encrypt_data()

        assert getattr(model.field1, "encrypted", False)
        assert getattr(model.field2, "encrypted", False)

    @pytest.mark.asyncio
    async def test_async_encrypt_data_disabled_is_noop(self):
        class _Model(BaseModel, disable=True):
            secret: Annotated[bytes, Encrypt]

        model = _Model(secret="plaintext")
        await model.async_encrypt_data()

        assert not getattr(model.secret, "encrypted", False)


class TestAsyncDecryptData:
    """Test async_decrypt_data method."""

    @pytest.mark.asyncio
    async def test_async_decrypt_data(self):
        class _EncryptModel(BaseModel):
            data: Annotated[bytes, Encrypt]

        class _DecryptModel(BaseModel):
            data: Annotated[bytes, Decrypt]

        encrypted = _EncryptModel(data="secret data")
        decrypt_model = _construct_without_crypto(_DecryptModel, **encrypted.model_dump())

        await decrypt_model.async_decrypt_data()
        assert decrypt_model.data == "secret data"

    @pytest.mark.asyncio
    async def test_async_decrypt_data_multiple_fields(self):
        class _EncryptModel(BaseModel):
            data1: Annotated[bytes, Encrypt]
            data2: Annotated[bytes, Encrypt]

        class _DecryptModel(BaseModel):
            data1: Annotated[bytes, Decrypt]
            data2: Annotated[bytes, Decrypt]

        encrypted = _EncryptModel(data1="secret1", data2="secret2")
        decrypt_model = _construct_without_crypto(_DecryptModel, **encrypted.model_dump())

        await decrypt_model.async_decrypt_data()
        assert decrypt_model.data1 == "secret1"
        assert decrypt_model.data2 == "secret2"


class TestAsyncHashData:
    """Test async_hash_data method."""

    @pytest.mark.asyncio
    async def test_async_hash_data(self):
        class _Model(BaseModel):
            password: Annotated[str, Hash]

        model = _construct_without_crypto(_Model, password="secret123")
        assert not getattr(model.password, "hashed", False)

        await model.async_hash_data()
        assert getattr(model.password, "hashed", False)

    @pytest.mark.asyncio
    async def test_async_hash_data_multiple_fields(self):
        class _Model(BaseModel):
            password1: Annotated[str, Hash]
            password2: Annotated[str, Hash]

        model = _construct_without_crypto(_Model, password1="secret1", password2="secret2")
        await model.async_hash_data()

        assert getattr(model.password1, "hashed", False)
        assert getattr(model.password2, "hashed", False)


class TestAsyncPostInit:
    """Test async_post_init method."""

    @pytest.mark.asyncio
    async def test_async_post_init_encrypt_and_hash(self):
        class _Model(BaseModel):
            email: Annotated[bytes, Encrypt]
            password: Annotated[str, Hash]

        model = _construct_without_crypto(_Model, email="user@example.com", password="secret123")
        assert not getattr(model.email, "encrypted", False)
        assert not getattr(model.password, "hashed", False)

        await model.async_post_init()

        assert getattr(model.email, "encrypted", False)
        assert getattr(model.password, "hashed", False)

    @pytest.mark.asyncio
    async def test_async_post_init_disabled_is_noop(self):
        class _Model(BaseModel, disable=True):
            secret: Annotated[bytes, Encrypt]

        model = _Model(secret="plaintext")
        await model.async_post_init()

        assert not getattr(model.secret, "encrypted", False)

    @pytest.mark.asyncio
    async def test_async_post_init_encrypt_then_decrypt(self):
        """async_post_init runs encrypt before decrypt (correct order)."""

        class _EncryptModel(BaseModel):
            data: Annotated[bytes, Encrypt]

        class _DecryptModel(BaseModel):
            data: Annotated[bytes, Decrypt]

        model = _construct_without_crypto(_EncryptModel, data="secret")
        await model.async_post_init()
        assert getattr(model.data, "encrypted", False)

        decrypt_model = _construct_without_crypto(_DecryptModel, **model.model_dump())
        await decrypt_model.async_post_init()
        assert decrypt_model.data == "secret"


class TestAsyncInitNestedModels:
    """Test async_init with nested SecureModel fields."""

    @pytest.mark.asyncio
    async def test_async_init_nested_model_encrypts(self):
        """Nested SecureModel fields have their crypto processed during async_init."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypt]

        class _User(BaseModel):
            name: str
            address: _Address

        user = await _User.async_init(name="John", address={"street": "123 Main St"})

        assert user.name == "John"
        assert getattr(user.address.street, "encrypted", False)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_hashes(self):
        """Nested SecureModel fields with Hash annotations are processed."""

        class _Credentials(BaseModel):
            password: Annotated[str, Hash]

        class _User(BaseModel):
            name: str
            credentials: _Credentials

        user = await _User.async_init(name="John", credentials={"password": "secret123"})

        assert user.name == "John"
        assert getattr(user.credentials.password, "hashed", False)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_mixed(self):
        """Parent and nested models both have crypto fields processed."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypt]

        class _User(BaseModel):
            email: Annotated[bytes, Encrypt]
            address: _Address

        user = await _User.async_init(email="john@example.com", address={"street": "123 Main St"})

        assert getattr(user.email, "encrypted", False)
        assert getattr(user.address.street, "encrypted", False)

    @pytest.mark.asyncio
    async def test_async_init_pre_constructed_nested_model(self):
        """Pre-constructed nested models (already encrypted) remain valid."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypt]

        class _User(BaseModel):
            name: str
            address: _Address

        address = _Address(street="123 Main St")  # sync crypto already ran
        assert getattr(address.street, "encrypted", False)

        user = await _User.async_init(name="John", address=address)

        assert user.name == "John"
        assert getattr(user.address.street, "encrypted", False)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_in_list(self):
        """SecureModel instances inside a list are recursively processed."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypt]

        class _User(BaseModel):
            name: str
            addresses: list[_Address]

        user = await _User.async_init(
            name="John",
            addresses=[{"street": "123 Main St"}, {"street": "456 Oak Ave"}],
        )

        assert user.name == "John"
        assert getattr(user.addresses[0].street, "encrypted", False)
        assert getattr(user.addresses[1].street, "encrypted", False)

    @pytest.mark.asyncio
    async def test_async_init_nested_model_in_dict(self):
        """SecureModel instances inside a dict are recursively processed."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypt]

        class _User(BaseModel):
            name: str
            addresses: dict[str, _Address]

        user = await _User.async_init(
            name="John",
            addresses={"home": {"street": "123 Main St"}, "work": {"street": "456 Oak Ave"}},
        )

        assert user.name == "John"
        assert getattr(user.addresses["home"].street, "encrypted", False)
        assert getattr(user.addresses["work"].street, "encrypted", False)

    @pytest.mark.asyncio
    async def test_async_post_init_disabled_parent_processes_nested_child(self):
        """A disabled parent still recursively processes non-disabled nested children."""

        class _Address(BaseModel):
            street: Annotated[bytes, Encrypt]

        class _User(BaseModel, disable=True):
            name: str
            address: _Address

        user = _construct_without_crypto(_User, name="John", address={"street": "123 Main St"})

        # Parent is disabled, nested child is not — child should still be processed
        await user.async_post_init()

        assert user.name == "John"
        assert getattr(user.address.street, "encrypted", False)


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
        assert not getattr(model.email, "blind_indexed", False)

        await model.async_blind_index_data()
        assert getattr(model.email, "blind_indexed", False)

    @pytest.mark.asyncio
    async def test_async_blind_index_argon2(self):
        class _Model(BaseModel):
            email: Annotated[bytes, BlindIndex(BlindIndexMethod.ARGON2)]

        model = _construct_without_crypto(_Model, email="test@example.com")

        await model.async_blind_index_data()
        assert getattr(model.email, "blind_indexed", False)

    @pytest.mark.asyncio
    async def test_async_blind_index_multiple_fields(self):
        class _Model(BaseModel):
            email: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]
            phone: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        model = _construct_without_crypto(_Model, email="test@example.com", phone="1234567890")
        await model.async_blind_index_data()

        assert getattr(model.email, "blind_indexed", False)
        assert getattr(model.phone, "blind_indexed", False)

    @pytest.mark.asyncio
    async def test_async_blind_index_disabled_is_noop(self):
        class _Model(BaseModel, disable=True):
            email: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        model = _Model(email="test@example.com")
        await model.async_blind_index_data()

        assert not getattr(model.email, "blind_indexed", False)

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


class TestAsyncEncryptDataErrors:
    """Test error branches in async encrypt/decrypt methods."""

    @pytest.mark.asyncio
    async def test_async_encrypt_data_missing_method_raises(self, monkeypatch):
        class _Model(BaseModel):
            secret: Annotated[bytes, Encrypt]

        model = _construct_without_crypto(_Model, secret="plaintext")
        monkeypatch.setattr(settings, "ENCRYPTION_METHOD", None)

        with pytest.raises(ValueError, match="ENCRYPTION_METHOD must be set"):
            await model.async_encrypt_data()

    @pytest.mark.asyncio
    async def test_async_decrypt_data_missing_method_raises(self, monkeypatch):
        class _EncryptModel(BaseModel):
            data: Annotated[bytes, Encrypt]

        class _DecryptModel(BaseModel):
            data: Annotated[bytes, Decrypt]

        encrypted = _EncryptModel(data="secret")
        decrypt_model = _construct_without_crypto(_DecryptModel, **encrypted.model_dump())
        monkeypatch.setattr(settings, "ENCRYPTION_METHOD", None)

        with pytest.raises(ValueError, match="ENCRYPTION_METHOD must be set"):
            await decrypt_model.async_decrypt_data()

    @pytest.mark.asyncio
    async def test_async_decrypt_data_disabled_is_noop(self):
        class _Model(BaseModel, disable=True):
            data: Annotated[bytes, Decrypt]

        model = _Model(data="something")
        await model.async_decrypt_data()

        assert model.data == b"something"

    @pytest.mark.asyncio
    async def test_async_hash_data_disabled_is_noop(self):
        class _Model(BaseModel, disable=True):
            password: Annotated[str, Hash]

        model = _Model(password="plaintext")
        await model.async_hash_data()

        assert not getattr(model.password, "hashed", False)

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
        await model.async_decrypt_data()
        assert model.name == "john"

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
