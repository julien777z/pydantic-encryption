# pydantic-encryption

Field-level encryption, hashing, and blind indexing for Pydantic models with SQLAlchemy integration.

## Installation

```bash
pip install pydantic-encryption
```

### Optional extras

```bash
pip install "pydantic-encryption[sqlalchemy]"  # SQLAlchemy integration
pip install "pydantic-encryption[aws]"         # AWS KMS encryption
pip install "pydantic-encryption[all]"         # All optional dependencies
```

## Quick Start

Mix `DeferredDecryptMixin` into any model with encrypted columns. The first time you read an encrypted attribute on any loaded row, the column is batch-decrypted across every sibling instance in the session — columns you never read stay encrypted and cost nothing:

```python
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from pydantic_encryption import DeferredDecryptMixin, SQLAlchemyEncryptedValue


class Base(DeclarativeBase):
    pass


class User(Base, DeferredDecryptMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[bytes] = mapped_column(SQLAlchemyEncryptedValue())


engine = create_async_engine("sqlite+aiosqlite:///:memory:")
Session = async_sessionmaker(engine, expire_on_commit=False)

async with Session() as session:
    session.add(User(email="john@example.com"))
    await session.commit()

    result = await session.execute(select(User))
    user = result.scalar_one()
    print(user.email)  # "john@example.com" — decrypted on first read
```

## SQLAlchemy Integration

Install with `pip install "pydantic-encryption[sqlalchemy]"`.

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session

from pydantic_encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyHashedValue,
    SQLAlchemyBlindIndexValue,
    BlindIndexMethod,
)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str]
    email: Mapped[bytes] = mapped_column(SQLAlchemyEncryptedValue())
    password: Mapped[bytes] = mapped_column(SQLAlchemyHashedValue())
    blind_index_email: Mapped[bytes] = mapped_column(
        SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)
    )


engine = create_engine("sqlite:///:memory:")
Base.metadata.create_all(engine)

with Session(engine) as session:
    user = User(
        username="john",
        email="john@example.com",
        password="secret123",
        blind_index_email="john@example.com",
    )
    session.add(user)
    session.commit()

    # Query by blind index — automatically hashed
    found = session.query(User).filter(
        User.blind_index_email == "john@example.com"
    ).first()
    print(found.email)  # decrypted
```

### Supported Types

`SQLAlchemyEncryptedValue` preserves the Python type of your data:

`str`, `bytes`, `bool`, `int`, `float`, `Decimal`, `UUID`, `date`, `datetime`, `time`, `timedelta`

### Array Support (PostgreSQL)

```python
from pydantic_encryption import SQLAlchemyPGEncryptedArray

tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray(), nullable=True)
```

Each element is individually encrypted. Requires PostgreSQL.

### Async Decryption

`TypeDecorator` is sync by contract, so slow backends (AWS KMS) can block the event loop. Two paths:

- **Default.** Under `AsyncSession`, decryption uses SQLAlchemy's greenlet bridge so each call yields the event loop. Argon2 hashing and blind-indexing use the same bridge.
- **On-access batch decrypt.** `DeferredDecryptMixin` defers each encrypted column until the first read, then batch-decrypts that column across every sibling instance loaded into the same session via a single `asyncio.gather`. Columns the caller never reads stay encrypted and cost nothing.

Mix the helper into any model with encrypted columns and read as usual:

```python
from pydantic_encryption import DeferredDecryptMixin, SQLAlchemyEncryptedValue


class User(Base, DeferredDecryptMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[bytes] = mapped_column(SQLAlchemyEncryptedValue())


Session = async_sessionmaker(engine, expire_on_commit=False)

async with Session() as session:
    result = await session.execute(select(User))
    users = result.scalars().all()

    # First read of `email` batch-decrypts it across every user in the session.
    for user in users:
        print(user.email)
```

`decrypt_pending_fields(session)` is an optional escape hatch when you need to pre-warm every encrypted column on every loaded row before leaving the session context (e.g. serializing outside a greenlet spawn):

```python
from pydantic_encryption import decrypt_pending_fields

async with Session() as session:
    users = (await session.execute(select(User))).scalars().all()

    # Decrypt every encrypted column on every row loaded so far.
    await decrypt_pending_fields(session)

    payload = [{"id": u.id, "email": u.email} for u in users]
```

**Manual helpers** for rows loaded outside a session or flat ciphertext lists:

```python
from pydantic_encryption import async_decrypt_rows, async_decrypt_values


async with AsyncSession(engine) as session:
    users = (await session.execute(select(User))).scalars().all()
    ciphertexts = [u.email for u in users]

    await users[0].decrypt()                                    # one mixin instance
    await User.decrypt_many(users)                              # batch of one class
    await async_decrypt_rows(users, User.email, concurrency=8)  # InstrumentedAttribute or column names
    await async_decrypt_values(ciphertexts, concurrency=8)      # flat ciphertexts; preserves None positions
```

### Safety: catching accidental ciphertext access

`EncryptedValue` is a `bytes` subclass, so anything that bypasses the on-access descriptor (raw `state.dict[col]`, a detached row passed to a FastAPI response, a log line on a pickled row) could silently emit ciphertext that *looks* like a value. Three guards make that loud:

- `repr(value)` returns `<EncryptedValue: N bytes>` instead of leaking raw ciphertext into logs.
- `str(value)`, `f"{value}"`, `"%s" % value` raise `EncryptedValueAccessError` with a message pointing at the decrypt path. Use `bytes(value)` if you explicitly want the raw ciphertext (backups, transport).
- `is_encrypted(value)` is a cheap public helper for boundary code that needs to guard a payload.

For workloads that pass ORM rows across async boundaries (queue workers, pickled rows), set `DECRYPT_STRICT_DETACHED=true`. With strict mode enabled, reading an encrypted column on a detached instance raises `EncryptedValueAccessError` instead of silently falling back to synchronous decrypt — forcing the caller to `await instance.decrypt()` or `await decrypt_pending_fields(session)` up front.

## Manual Encryption or Hashing

Fields annotated with `Encrypted` are encrypted and fields annotated with `Hashed` are hashed during model initialization:

```python
from typing import Annotated
from pydantic_encryption import BaseModel, Encrypted, Hashed

class User(BaseModel):
    name: str
    address: Annotated[bytes, Encrypted]
    password: Annotated[str, Hashed]

user = User(name="John Doe", address="123 Main St", password="secret123")

print(user.name)      # "John Doe"
print(user.address)   # encrypted bytes
print(user.password)  # argon2 hash bytes
```

### Decrypting

Call `decrypt_data()` to decrypt all `Encrypted` fields in-place. It returns `self`, so it can be chained:

```python
user = User(name="John", address="123 Main St", password="secret")
user.decrypt_data()
print(user.address)  # "123 Main St"
```

### Async Support

Use `async_init()` to construct models with async encryption, hashing, and blind indexing, and `async_decrypt_data()` for async decryption:

```python
user = await User.async_init(name="John", address="123 Main St", password="secret")
await user.async_decrypt_data()
```

All phases (encrypt, hash, blind-index) run concurrently via `asyncio.gather`, and nested `BaseModel` instances — including those inside `list`, `tuple`, `dict`, and `set` containers — are processed recursively.

## Encryption Methods

Set the encryption method via environment variable:

```bash
ENCRYPTION_METHOD=fernet   # Fernet symmetric encryption (requires ENCRYPTION_KEY)
ENCRYPTION_METHOD=aws      # AWS KMS (requires AWS_KMS_KEY_ARN, AWS_KMS_REGION, etc.)
```

There is no default — you must explicitly set `ENCRYPTION_METHOD` if using `Encrypted` fields.

### Fernet Setup

```bash
# Generate a key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Set environment variables
ENCRYPTION_METHOD=fernet
ENCRYPTION_KEY=your_generated_key
```

### AWS KMS Setup

```bash
ENCRYPTION_METHOD=aws
AWS_KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789:key/your-key-id
AWS_KMS_REGION=us-east-1
AWS_KMS_ACCESS_KEY_ID=your_access_key
AWS_KMS_SECRET_ACCESS_KEY=your_secret_key
```

As an alternative to `AWS_KMS_KEY_ARN`, separate encrypt/decrypt keys are supported for key rotation or read-only scenarios:

```bash
AWS_KMS_ENCRYPT_KEY_ARN=arn:aws:kms:...encrypt-key
AWS_KMS_DECRYPT_KEY_ARN=arn:aws:kms:...decrypt-key
```

Use one mode or the other — combining `AWS_KMS_KEY_ARN` with either split variant raises a validation error. A decrypt-only key alone is allowed (read-only workloads).

#### Plaintext cache (opt-in)

For read-heavy workloads that repeatedly decrypt the same ciphertexts, AWS KMS round-trips dominate. An in-process LRU of ciphertext → plaintext is available as opt-in:

```bash
AWS_KMS_PLAINTEXT_CACHE_ENABLED=true      # default: false
AWS_KMS_PLAINTEXT_CACHE_CAPACITY=2048     # default: 2048 entries
```

Disabled by default because cache entries hold decrypted sensitive data in a process-wide `cachetools.LRUCache` for the lifetime of the process. Enable it when the perf win outweighs keeping plaintext resident in memory.

### Model-Level Config

Override encryption settings per model instead of relying on environment variables:

```python
from pydantic_encryption import BaseModel, Encrypted, EncryptionMethod
from typing import Annotated

class SpecialUser(BaseModel, encryption_method=EncryptionMethod.FERNET, encryption_key="my-key"):
    email: Annotated[bytes, Encrypted]
```

Supported kwargs: `encryption_method`, `encryption_key`, `blind_index_key`. Falls back to env vars if not set.

## Blind Indexes

Blind indexes enable equality searches on encrypted data by storing a deterministic keyed hash alongside the ciphertext.

**Configuration:** Set `BLIND_INDEX_SECRET_KEY` via environment variable.

### Pydantic Models

```python
from typing import Annotated
from pydantic_encryption import BaseModel, BlindIndex, BlindIndexMethod

class User(BaseModel):
    email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]
```

### Normalization

Normalize values before hashing to ensure consistent lookups:

```python
email_index: Annotated[bytes, BlindIndex(
    BlindIndexMethod.HMAC_SHA256,
    normalize_to_lowercase=True,
    strip_whitespace=True,
)]
```

Available options:

| Option | Effect |
|--------|--------|
| `strip_whitespace` | Strip leading/trailing whitespace, collapse internal whitespace |
| `strip_non_characters` | Remove all non-letter characters (keep only a-zA-Z) |
| `strip_non_digits` | Remove all non-digit characters (keep only 0-9) |
| `normalize_to_lowercase` | Convert to lowercase |
| `normalize_to_uppercase` | Convert to uppercase |

### Methods

| Method | Description |
|--------|-------------|
| `BlindIndexMethod.HMAC_SHA256` | Fast HMAC-SHA256 keyed hash. Standard choice. |
| `BlindIndexMethod.ARGON2` | Memory-hard Argon2 hash with deterministic salt. Better brute-force resistance. |

## Custom Encryption or Hashing

Subclass `BaseModel` and override any of `encrypt_data`, `hash_data`, `blind_index_data` (or their async variants) to plug in your own logic. The post-init hook runs automatically:

```python
from pydantic_encryption import BaseModel

class MyModel(BaseModel):
    def encrypt_data(self) -> None:
        # your encryption logic (mutate self in-place)
        ...
```

To implement a new backend instead of replacing the per-model path, subclass one of the adapter ABCs (`EncryptionAdapter`, `HashingAdapter`, `BlindIndexAdapter`) and register it via `register_encryption_backend` / `register_blind_index_backend`. Async variants are inherited by default — override `async_encrypt` / `async_decrypt` only for natively-async backends.

## Run Tests

```bash
pip install -e ".[dev]"
pytest -v
```
