import asyncio
import subprocess
import sys
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Annotated
from uuid import uuid4

import pytest
from cryptography.fernet import InvalidToken
from pydantic import ValidationError
from pydantic_super_model import AnnotatedFieldInfo

from pydantic_encryption import BaseModel, BlindIndex, BlindIndexMethod, Encrypted, Hashed
from pydantic_encryption.adapters.blind_index.hmac_sha256 import HMACSHA256Adapter
from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.context import derive_field_context
from pydantic_encryption.serialization import decode_value
from pydantic_encryption.types import BlindIndexValue, EncryptedValue, HashedValue
from tests.factories import User
from tests.models.records import (
    AnyEncryptedRecord,
    EncryptedRecord,
    HashedRecord,
    IndexedRecord,
    MixedRecord,
    NestedRecord,
    OptionalIndexedRecord,
    OptionalRecord,
    PlainRecord,
)
from tests.unit.models.utils import NO_SQLALCHEMY_SCRIPT, build, decrypt, deferred_crypto

ASYNC_PATHS = pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])


@pytest.mark.asyncio
class TestSecureModel:
    """Test how a model encrypts, hashes, blind-indexes and decrypts its annotated fields."""

    @ASYNC_PATHS
    async def test_annotated_fields_processed(self, asynchronous: bool, user: User):
        """Test that construction encrypts, hashes and indexes annotated fields but not plain ones."""

        record = await build(
            MixedRecord,
            asynchronous,
            name=user.first_name,
            secret=user.last_name,
            password=user.last_name,
            email_index=user.username,
        )

        assert record.name == user.first_name
        assert isinstance(record.secret, EncryptedValue)
        assert isinstance(record.password, HashedValue)
        assert record.password.startswith(b"$argon2")
        assert isinstance(record.email_index, BlindIndexValue)

    async def test_sync_construction_seals_after_async_init(self):
        """Test that async construction leaves later sync construction sealing as before."""

        await EncryptedRecord.async_init(secret="secret data")

        assert isinstance(EncryptedRecord(secret="secret data").secret, EncryptedValue)

    @ASYNC_PATHS
    @pytest.mark.parametrize(
        "value",
        [
            "",
            "   ",
            "secret data",
            "日本語 🔐 العربية",
            "x" * 10000,
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
            "empty",
            "whitespace",
            "str",
            "unicode",
            "long",
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
    async def test_round_trip_preserves_type(self, asynchronous: bool, value: object):
        """Test that a field decrypts back to the value it held, of exactly its type."""

        record = await build(AnyEncryptedRecord, asynchronous, data=value)

        assert isinstance(record.data, EncryptedValue)
        assert await decrypt(record, asynchronous) is record
        assert record.data == value
        assert type(record.data) is type(value)

    @ASYNC_PATHS
    async def test_unencrypted_model_decrypts_to_self(self, asynchronous: bool):
        """Test that decrypting a model with no encrypted field changes nothing and returns it."""

        record = await build(PlainRecord, asynchronous, name="sample name")

        assert await decrypt(record, asynchronous) is record
        assert record.name == "sample name"

    @ASYNC_PATHS
    async def test_empty_optional_fields_stay_empty(self, asynchronous: bool):
        """Test that optional fields left empty, or set to None, are neither encrypted nor hashed."""

        assert (await build(OptionalRecord, asynchronous)).model_dump() == {"secret": None, "password": None}
        assert (await build(OptionalRecord, asynchronous, password=None)).password is None

    @ASYNC_PATHS
    async def test_nested_models_processed(self, asynchronous: bool):
        """Test that models held directly or inside any container have their own fields encrypted."""

        record = await build(
            NestedRecord,
            asynchronous,
            secret="secret data",
            child={"secret": "child secret"},
            children=[{"secret": "first"}],
            groups=[[{"secret": "first"}], [{"secret": "second"}]],
            by_name={"first": {"secret": "first"}},
            groups_by_name={"first": [{"secret": "first"}, {"secret": "second"}]},
        )
        children = [
            record.child,
            *record.children,
            *(child for group in record.groups for child in group),
            *record.by_name.values(),
            *(child for group in record.groups_by_name.values() for child in group),
        ]

        assert isinstance(record.secret, EncryptedValue)
        assert len(children) == 7
        assert all(isinstance(child.secret, EncryptedValue) for child in children)

    async def test_constructed_child_kept_sealed(self):
        """Test that a child model sealed before its parent's async construction is not sealed again."""

        child = EncryptedRecord(secret="child secret")
        sealed = child.secret

        record = await NestedRecord.async_init(secret="secret data", child=child)

        assert record.child.secret == sealed
        assert (await record.child.async_decrypt_data()).secret == "child secret"

    @ASYNC_PATHS
    async def test_ciphertext_kept_as_given(self, asynchronous: bool):
        """Test that a field given an existing ciphertext keeps it rather than sealing it again."""

        sealed = AnyEncryptedRecord(data="secret data").data

        record = await build(AnyEncryptedRecord, asynchronous, data=sealed)

        assert record.data == sealed
        assert (await decrypt(record, asynchronous)).data == "secret data"

    async def test_inherited_fields_processed(self):
        """Test that a subclass encrypts and hashes the annotated fields it declares beside inherited ones."""

        class SecretRecord(PlainRecord):
            password: Annotated[str, Hashed]
            secret: Annotated[str, Encrypted]

        record = SecretRecord(name="sample name", password="sample password", secret="secret data")

        assert record.name == "sample name"
        assert isinstance(record.password, HashedValue)
        assert isinstance(record.secret, EncryptedValue)

    async def test_dump_carries_processed_values(self):
        """Test that a dump carries the ciphertext and hash rather than the plaintext."""

        record = MixedRecord(
            name="sample name", secret="secret data", password="secret data", email_index="sample"
        )
        dumped = record.model_dump()

        assert dumped["secret"] == record.secret
        assert dumped["password"] == record.password
        assert b"secret data" not in (dumped["secret"], dumped["password"])

    @pytest.mark.parametrize(
        ("record", "data", "expected"),
        [
            (EncryptedRecord, {"secret": "secret data"}, ["secret"]),
            (OptionalRecord, {"secret": None}, ["secret"]),
            (OptionalRecord, {}, []),
        ],
        ids=["value", "explicit-none", "default-none"],
    )
    async def test_annotated_field_lookup(
        self, record: type[BaseModel], data: dict[str, str | None], expected: list[str]
    ):
        """Test that the lookup lists fields given a value or an explicit None, and omits defaults."""

        fields = record(**data).get_annotated_fields(Encrypted)

        assert list(fields) == expected
        assert all(isinstance(field, AnnotatedFieldInfo) for field in fields.values())
        assert all(field.matched_metadata == (Encrypted,) for field in fields.values())

    @pytest.mark.parametrize(
        ("record", "data", "phase", "expected_type"),
        [
            (EncryptedRecord, {"secret": "secret data"}, "async_encrypt_data", EncryptedValue),
            (HashedRecord, {"password": "secret data"}, "async_hash_data", HashedValue),
            (IndexedRecord, {"email_index": "sample"}, "async_blind_index_data", BlindIndexValue),
        ],
        ids=["encrypt", "hash", "blind-index"],
    )
    async def test_async_phase_processes_deferred_fields(
        self, record: type[BaseModel], data: dict[str, str], phase: str, expected_type: type[bytes]
    ):
        """Test that each async phase processes the fields deferred construction left untouched."""

        with deferred_crypto():
            model = record(**data)

        (field,) = data

        assert not isinstance(getattr(model, field), expected_type)

        await getattr(model, phase)()

        assert isinstance(getattr(model, field), expected_type)

    async def test_async_post_init_runs_every_phase(self):
        """Test that the async post-init encrypts, hashes and indexes a deferred model."""

        with deferred_crypto():
            record = MixedRecord(
                name="sample name", secret="secret data", password="secret", email_index="sample"
            )

        await record.async_post_init()

        assert isinstance(record.secret, EncryptedValue)
        assert isinstance(record.password, HashedValue)
        assert isinstance(record.email_index, BlindIndexValue)

    @pytest.mark.parametrize(
        "phase", ["async_encrypt_data", "async_decrypt_data", "async_hash_data", "async_blind_index_data"]
    )
    async def test_async_phase_without_fields_changes_nothing(self, phase: str):
        """Test that an async phase over a model with nothing to process leaves it as it was."""

        with deferred_crypto():
            record = PlainRecord(name="sample name")

        await getattr(record, phase)()

        assert record.name == "sample name"

    @ASYNC_PATHS
    async def test_unset_method_refused(self, monkeypatch: pytest.MonkeyPatch, asynchronous: bool):
        """Test that encrypting or decrypting raises when no encryption method is configured."""

        with deferred_crypto():
            record = EncryptedRecord(secret="secret data")

        monkeypatch.setattr(settings, "ENCRYPTION_METHOD", None)

        with pytest.raises(ValueError, match="ENCRYPTION_METHOD must be set"):
            if asynchronous:
                await record.async_encrypt_data()
            else:
                record.encrypt_data()

        with pytest.raises(ValueError, match="ENCRYPTION_METHOD must be set"):
            await decrypt(record, asynchronous)

    async def test_async_init_validates_input(self):
        """Test that async construction still validates its input."""

        class AgedRecord(EncryptedRecord):
            age: int

        with pytest.raises(ValidationError):
            await AgedRecord.async_init(age="not a number", secret="secret data")

    @ASYNC_PATHS
    @pytest.mark.parametrize("method", list(BlindIndexMethod))
    async def test_blind_index_is_deterministic_digest(
        self, asynchronous: bool, method: BlindIndexMethod, user: User, other_user: User
    ):
        """Test that a value indexes to the same 32-byte digest on both paths, and another value differs."""

        class MethodRecord(BaseModel):
            email_index: Annotated[str | bytes, BlindIndex(method)]

        first = (await build(MethodRecord, asynchronous, email_index=user.username)).email_index

        assert isinstance(first, BlindIndexValue)
        assert len(first) == 32
        assert first == MethodRecord(email_index=user.username).email_index
        assert first != MethodRecord(email_index=other_user.username).email_index

    async def test_blind_index_reads_bytes_as_text(self, user: User):
        """Test that UTF-8 bytes index the same as the text they encode."""

        assert (
            IndexedRecord(email_index=user.username.encode("utf-8")).email_index
            == IndexedRecord(email_index=user.username).email_index
        )

    async def test_blind_index_methods_differ(self, user: User):
        """Test that the two methods index one value differently."""

        class Argon2Record(BaseModel):
            email_index: Annotated[str | bytes, BlindIndex(BlindIndexMethod.ARGON2)]

        assert (
            IndexedRecord(email_index=user.username).email_index
            != Argon2Record(email_index=user.username).email_index
        )

    async def test_blind_index_kept_as_given(self, user: User):
        """Test that a field already holding a blind index is not indexed again."""

        index = IndexedRecord(email_index=user.username).email_index

        assert IndexedRecord(email_index=index).email_index == index

    async def test_text_only_field_indexed(self, user: User):
        """Test that a field declared as text alone is indexed through the async path."""

        class TextIndexedRecord(BaseModel):
            email_index: Annotated[str, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        record = await TextIndexedRecord.async_init(email_index=user.username)

        assert record.email_index == IndexedRecord(email_index=user.username).email_index

    @ASYNC_PATHS
    async def test_missing_index_key_refused(self, monkeypatch: pytest.MonkeyPatch, asynchronous: bool):
        """Test that indexing raises without BLIND_INDEX_SECRET_KEY, unless the field is empty."""

        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", None)

        assert (await build(OptionalIndexedRecord, asynchronous)).email_index is None

        with deferred_crypto():
            record = IndexedRecord(email_index="sample")

        with pytest.raises(ValueError, match="BLIND_INDEX_SECRET_KEY must be set"):
            if asynchronous:
                await record.async_blind_index_data()
            else:
                record.blind_index_data()

    async def test_bare_blind_index_class_refused(self):
        """Test that annotating with the BlindIndex class instead of an instance raises."""

        class BareIndexRecord(BaseModel):
            email_index: Annotated[str | bytes, BlindIndex]

        with pytest.raises(TypeError, match="must be annotated with a BlindIndex"):
            BareIndexRecord(email_index="sample")

    @pytest.mark.parametrize(
        ("flags", "message"),
        [
            (
                {"strip_non_characters": True, "strip_non_digits": True},
                "strip_non_characters and strip_non_digits cannot both be True",
            ),
            (
                {"normalize_to_lowercase": True, "normalize_to_uppercase": True},
                "normalize_to_lowercase and normalize_to_uppercase cannot both be True",
            ),
        ],
        ids=["strip", "case"],
    )
    async def test_conflicting_index_flags_refused(self, flags: dict[str, bool], message: str):
        """Test that two normalization flags that contradict each other are refused."""

        with pytest.raises(ValueError, match=message):
            BlindIndex(BlindIndexMethod.HMAC_SHA256, **flags)

    @pytest.mark.parametrize(
        ("flags", "raw", "normalized"),
        [
            ({"normalize_to_lowercase": True}, "Hello@Example.COM", "hello@example.com"),
            ({"strip_whitespace": True}, "  first   second  ", "first second"),
            ({"strip_trailing_punctuation": True}, "first second.", "first second"),
            ({"strip_non_digits": True}, "a1 (b2) c3-d4", "1234"),
        ],
        ids=["lowercase", "strip-whitespace", "strip-trailing-punctuation", "strip-non-digits"],
    )
    async def test_raw_value_indexed_as_normalized(self, flags: dict[str, bool], raw: str, normalized: str):
        """Test that a raw value indexes the same as its normalized form."""

        class NormalizedRecord(BaseModel):
            email_index: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256, **flags)]

        assert (
            NormalizedRecord(email_index=raw).email_index
            == NormalizedRecord(email_index=normalized).email_index
        )

    @pytest.mark.parametrize(
        "marker", [Hashed, BlindIndex(BlindIndexMethod.HMAC_SHA256)], ids=["hashed", "blind-index"]
    )
    async def test_non_text_digest_field_refused(self, marker: object):
        """Test that hashing or indexing a field holding neither str nor bytes names the field it refused."""

        class PinRecord(BaseModel):
            pin: Annotated[int, marker]

        with pytest.raises(TypeError, match="'pin'"):
            PinRecord(pin=1234)

    async def test_non_text_ciphertext_refused(self):
        """Test that decrypting a field reassigned to a non-ciphertext value names the field it refused."""

        class JoinedRecord(BaseModel):
            joined_on: Annotated[date, Encrypted]

        record = JoinedRecord(joined_on=date(1990, 5, 4))
        record.joined_on = date(1990, 5, 5)

        with pytest.raises(TypeError, match="'joined_on'"):
            record.decrypt_data()

    @pytest.mark.parametrize("value", [["secret"], {"secret": 1}], ids=["list", "dict"])
    async def test_unsupported_type_refused(self, value: object):
        """Test that a value of a type no encrypted value holds is refused instead of stored as its repr."""

        with pytest.raises(TypeError, match=repr(type(value).__name__)):
            AnyEncryptedRecord(data=value)

    async def test_encryption_needs_no_sqlalchemy(self):
        """Test that encrypting a model field needs nothing from the SQLAlchemy integration."""

        environment = {
            "ENCRYPTION_METHOD": "fernet",
            "ENCRYPTION_KEY": settings.ENCRYPTION_KEY or "",
            "PATH": "/usr/bin:/bin",
        }

        result = await asyncio.to_thread(
            subprocess.run,
            [sys.executable, "-c", NO_SQLALCHEMY_SCRIPT],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )

        assert result.returncode == 0, result.stderr

    async def test_declared_method_and_key_used(self, monkeypatch: pytest.MonkeyPatch, fernet_key: str):
        """Test that a model declaring its method by name and its key seals under them, not the settings."""

        class DeclaredRecord(BaseModel, encryption_method="fernet", encryption_key=fernet_key):
            secret: Annotated[str, Encrypted]

        monkeypatch.setattr(settings, "ENCRYPTION_METHOD", None)
        record = DeclaredRecord(secret="secret data")
        plaintext = FernetAdapter.decrypt(
            record.secret, key=fernet_key, associated_data=record.field_context("secret")
        )

        assert decode_value(plaintext) == "secret data"
        assert record.decrypt_data().secret == "secret data"

    async def test_declared_index_key_used(self, user: User):
        """Test that a model declaring a blind index key indexes under it, not BLIND_INDEX_SECRET_KEY."""

        class DeclaredIndexRecord(BaseModel, blind_index_key="sample-model-index-key"):
            email_index: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        assert DeclaredIndexRecord(
            email_index=user.username
        ).email_index == HMACSHA256Adapter.compute_blind_index(user.username, b"sample-model-index-key")

    async def test_undeclared_model_reads_settings(self):
        """Test that a model declaring no settings seals under the configured method and key."""

        record = EncryptedRecord(secret="secret data")
        plaintext = FernetAdapter.decrypt(record.secret, associated_data=record.field_context("secret"))

        assert decode_value(plaintext) == "secret data"

    async def test_field_context_names_model_and_field(self, user: User):
        """Test that a field's context spells out its module, class and field name."""

        assert user.field_context("address") == derive_field_context(User.__module__, "User", "address")

    async def test_ciphertext_bound_to_its_field(self, user: User):
        """Test that one field's ciphertext fails to open under a sibling field's context."""

        assert user.field_context("address") != user.field_context("username")

        with pytest.raises(InvalidToken):
            FernetAdapter.decrypt(user.address, associated_data=user.field_context("username"))
