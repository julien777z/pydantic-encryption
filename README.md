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

Fields marked with `Encrypted` are encrypted and fields marked with `Hashed` are hashed during model initialization.

### Decrypting

Call `decrypt_fields()` on the model instance to decrypt all `Encrypted` fields in-place:

```python
user = User(name="John", address="123 Main St", password="secret")

user.decrypt_fields()
print(user.address)  # "123 Main St"
```

`decrypt_fields()` returns `self`, so it can be chained.

## Async Support

Use `async_init()` to construct models with async encryption, hashing, and blind indexing:

```python
user = await User.async_init(name="John", address="123 Main St", password="secret")
```

Use `async_decrypt_fields()` for async decryption:

```python
await user.async_decrypt_fields()
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

### Async SQLAlchemy Decryption

SQLAlchemy's `TypeDecorator` is sync by contract — even under `AsyncSession` the result-processing pipeline runs inline. For fast backends (Fernet) this is fine, but a network-bound backend like AWS KMS can spend tens of milliseconds per call, blocking the event loop.

`pydantic-encryption` handles this with a two-tier strategy:

**Tier 1 — automatic, zero code change.** Under `AsyncSession`, decryption transparently uses SQLAlchemy's greenlet bridge (`sqlalchemy.util.await_`) so each decrypt yields the event loop during its network roundtrip. Other tasks on the loop keep progressing. The same bridge also wraps Argon2 hashing (`SQLAlchemyHashedValue`) and Argon2 blind-index computation (`SQLAlchemyBlindIndexValue`) so write-side commits don't block either.

**Tier 2 — opt-in, real parallelism.** For single fetches with many encrypted cells, pass `defer_decrypt=True` on the column and bulk-decrypt after the fetch. Every cell is decrypted concurrently via `asyncio.gather`, turning N sequential roundtrips into one concurrent burst.

```python
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic_encryption import async_decrypt_rows, SQLAlchemyEncryptedValue

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[bytes] = mapped_column(SQLAlchemyEncryptedValue(defer_decrypt=True))
    secret: Mapped[bytes] = mapped_column(SQLAlchemyEncryptedValue(defer_decrypt=True))


async with AsyncSession(engine) as session:
    users = (await session.execute(select(User).limit(1000))).scalars().all()

    # Before this call, users[i].email is still an EncryptedValue.
    await async_decrypt_rows(users, User.email, User.secret)

    for u in users:
        print(u.email)  # decrypted plaintext
```

`async_decrypt_rows` accepts `InstrumentedAttribute` (e.g. `User.email`) or string column names. Pass `concurrency=N` to cap in-flight decrypts with an `asyncio.Semaphore`.

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
