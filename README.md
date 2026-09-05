# Pydantic Encryption

Field-level encryption, hashing, and blind indexing for Pydantic models, with SQLAlchemy column types for the same.

## Features

- Encrypted, hashed, and blind-indexed fields on Pydantic models
- SQLAlchemy column types for encrypted values, hashes, blind indexes, and PostgreSQL arrays
- Every ciphertext bound to the column, row, or field it belongs to, and refused anywhere else
- Values return as the Python type they were stored as, not as bytes
- Fernet and AWS KMS backends, or your own
- Sync and async paths, with decryption batched across a session and deferred to first read
- Blind indexes for equality search over encrypted data, with normalization and per-row salts

## Installation

```bash
pip install pydantic-encryption
```

Optional extras:

```bash
pip install "pydantic-encryption[sqlalchemy]"  # SQLAlchemy integration
pip install "pydantic-encryption[aws]"         # AWS KMS encryption
pip install "pydantic-encryption[all]"         # All optional dependencies
```

## Quick Start

Annotate a field with `Encrypted` or `Hashed` and it is processed during model initialization:

```python
from datetime import date
from typing import Annotated
from pydantic_encryption import BaseModel, Encrypted, Hashed


class User(BaseModel):
    name: str
    address: Annotated[str, Encrypted]
    joined_on: Annotated[date, Encrypted]
    password: Annotated[str, Hashed]


user = User(name="John Doe", address="123 Main St", joined_on=date(2026, 1, 2), password="secret123")

print(user.name)      # "John Doe"
print(user.address)   # encrypted bytes
print(user.password)  # argon2 hash bytes

user.decrypt_data()
print(user.address)    # "123 Main St"
print(user.joined_on)  # datetime.date(2026, 1, 2)
```

`decrypt_data()` decrypts every `Encrypted` field in place and returns `self`, so it can be chained. A field comes back as the type it declares, so `joined_on` decrypts to a `date` rather than to the string it was serialized as.

## Configuration

Set the encryption method via environment variable. There is no default — it must be set explicitly to use `Encrypted` fields.

```bash
ENCRYPTION_METHOD=aws      # AWS KMS (requires AWS_KMS_KEY_ARN, AWS_KMS_REGION, etc.)
ENCRYPTION_METHOD=fernet   # Fernet symmetric encryption (requires ENCRYPTION_KEY)
```

### Fernet

```bash
# Generate a key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Set environment variables
ENCRYPTION_METHOD=fernet
ENCRYPTION_KEY=your_generated_key
```

`ENCRYPTION_KEY` is the root key. Each context's key is derived from it with HKDF-SHA256 as the value is sealed or opened, so one key covers every column and a token still only opens under the context it was sealed for.

### AWS KMS

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

One KMS data key seals many values, and an unwrapped data key opens many, so KMS is called once per key rather than once per value. The bounds on that reuse are settings:

| Setting | Default | Bounds |
|---------|---------|--------|
| `AWS_KMS_DATA_KEY_MAX_USES` | `1000` | Values one data key seals before a fresh one is generated |
| `AWS_KMS_DATA_KEY_MAX_AGE_SECONDS` | `300` | How long one data key seals values before a fresh one is generated |
| `AWS_KMS_UNWRAPPED_KEY_CACHE_SIZE` | `512` | Unwrapped data keys held in memory, least recently used evicted first |
| `AWS_KMS_UNWRAPPED_KEY_MAX_AGE_SECONDS` | `300` | How long an unwrapped data key is held before KMS unwraps it again |

Every value still carries its own nonce and its own context, so sharing a data key changes how often KMS is called and nothing about what a ciphertext opens under.

### Per Model

Override encryption settings on a model instead of relying on environment variables:

```python
from typing import Annotated
from pydantic_encryption import BaseModel, Encrypted, EncryptionMethod


class SpecialUser(BaseModel, encryption_method=EncryptionMethod.FERNET, encryption_key="my-key"):
    email: Annotated[bytes, Encrypted]
```

Supported kwargs: `encryption_method`, `encryption_key`, `blind_index_key`. Falls back to env vars if not set.

## Supported Types

Encrypted columns and `Encrypted` model fields alike preserve the Python type of your data:

`str`, `bytes`, `bool`, `int`, `float`, `Decimal`, `UUID`, `date`, `datetime`, `time`, `timedelta`

## Async Models

Use `async_init()` to construct models with async encryption, hashing, and blind indexing, and `async_decrypt_data()` for async decryption:

```python
user = await User.async_init(
    name="John", address="123 Main St", joined_on=date(2026, 1, 2), password="secret"
)
await user.async_decrypt_data()
```

All phases (encrypt, hash, blind-index) run concurrently via `asyncio.gather`, and nested `BaseModel` instances — including those inside `list`, `tuple`, `dict`, and `set` containers — are processed recursively.

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

### Arrays (PostgreSQL)

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
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker
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

`finalize_sqlalchemy_session(session)` combines the above with a `commit()`, returning the pooled connection before response construction. Handy on read endpoints that would otherwise hold a DB connection through descriptor-driven KMS decryption:

```python
from pydantic_encryption import finalize_sqlalchemy_session

async with Session() as session:
    users = (await session.execute(select(User))).scalars().all()
    await finalize_sqlalchemy_session(session)  # decrypt pending + commit — connection released
    return [{"id": u.id, "email": u.email} for u in users]
```

**Manual helpers** for rows loaded outside a session or flat ciphertext lists:

```python
from pydantic_encryption import decrypt_rows, decrypt_values


async with AsyncSession(engine) as session:
    users = (await session.execute(select(User))).scalars().all()
    ciphertexts = [u.email for u in users]

    await users[0].decrypt()                              # one mixin instance
    await User.decrypt_many(users)                        # batch of one class
    await decrypt_rows(users, User.email)                 # InstrumentedAttribute or column names
    await decrypt_values(ciphertexts, context=User.email)     # flat ciphertexts; preserves None positions
```

### Catching Accidental Ciphertext Access

Reads go through the on-access descriptor. When the underlying cell is still an `EncryptedValue`, the descriptor prefers an async batch decrypt over the session's pending siblings (via SQLAlchemy's greenlet bridge), and transparently falls back to a synchronous decrypt either when the read happens outside a greenlet or when the instance is detached from any session.

An `EncryptedValue` only reaches user code if something bypasses the descriptor entirely (raw `state.dict[col]`, a logged row). Coercing it via `str(value)` / `f"{value}"` / `"%s" % value` raises `EncryptedValueAccessError`. `repr(value)` is a safe `<EncryptedValue: N bytes>` marker, and `bytes(value)` returns the raw ciphertext. Use `is_encrypted(value)` to guard at a boundary.

## Context Binding

Every ciphertext is bound to the context it belongs to. That context is authenticated on encrypt and required on decrypt, so a value lifted out of one column fails to open anywhere else.

Contexts are derived, so there is nothing to pass in the common case:

| Value | Context |
|-------|---------|
| A column | `table.column`, or `schema.table.column` where the table names a schema |
| An array element | the context of the array column itself |
| A model field | `module.Model.field` |

A column inherited from a mixin binds separately for each table that inherits it, and one type binds one column — a type already attached to a column refuses a second. A separator inside a name is escaped, so no two locations can share a context however they are named. `derive_column_context` and `derive_field_context` apply these rules, so a migration can name what a value binds to without reimplementing them:

```python
from pydantic_encryption import derive_column_context

derive_column_context("users", "email")                    # b"users.email"
derive_column_context("users", "email", schema="archive")  # b"archive.users.email"
```

The context is authenticated but never written into the ciphertext, so it is part of the column's contract: renaming a table or column re-binds what it writes from then on, and values stored under the old name no longer open.

Pass a context explicitly only where nothing can be derived, such as a value that never reaches a column:

```python
draft = SQLAlchemyEncryptedValue("records.draft").encrypt_cell(payload)
```

### Binding a Cell to Its Row

A column context stops a ciphertext moving between columns. `row_bound=True` also stops one moving between rows of the same column:

```python
secret: Mapped[bytes] = mapped_column(SQLAlchemyEncryptedValue(row_bound=True))
```

Each cell then binds to `schema.table.column.<primary key>`, which `derive_row_context` names. A row-bound column requires two things, and says so rather than binding something weaker:

- **`DeferredDecryptMixin` on the mapped class.** A column type sees only the value it is handed, never the row, so row-bound cells seal as the row is inserted or updated and open through the deferred read path, which has the instance.
- **A primary key that exists before the insert** — one the application assigns, or one with a client-side default such as `default=uuid.uuid4`. A server-generated key does not exist until after the insert it would have to be written into.

Changing a row's primary key re-seals its row-bound cells under the key it moves to, so the row keeps reading.

Encrypted arrays decrypt on the read path, where no row is in scope, so they bind their column and refuse `row_bound`.

### Backends

Both backends bind, and one whose primitive could not authenticate a context raises rather than ignoring it. AWS KMS authenticates the context in the AES-GCM tag. A Fernet token has no field for it, so Fernet binds by key separation instead: each context gets its own key derived from `ENCRYPTION_KEY`, and a token carried into another context fails its authentication check there.

## Blind Indexes

Blind indexes enable equality searches on encrypted data by storing a deterministic keyed hash alongside the ciphertext. Set `BLIND_INDEX_SECRET_KEY` via environment variable.

```python
from typing import Annotated
from pydantic_encryption import BaseModel, BlindIndex, BlindIndexMethod


class User(BaseModel):
    email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]
```

### Methods

| Method | Description |
|--------|-------------|
| `BlindIndexMethod.HMAC_SHA256` | Fast HMAC-SHA256 keyed hash. Standard choice. |
| `BlindIndexMethod.ARGON2` | Memory-hard Argon2 hash with deterministic salt. Better brute-force resistance. |

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
| `strip_trailing_punctuation` | Remove trailing periods and commas from each whitespace-separated token, dropping any token left empty |
| `normalize_to_lowercase` | Convert to lowercase |
| `normalize_to_uppercase` | Convert to uppercase |

Normalization determines the hashed value, so changing a field's flags changes the indexes computed for the values those flags touch. Recompute stored indexes when flags change.

### Computing Indexes Directly

`make_blind_index` computes a `BlindIndexValue` outside the annotation/column path — handy for query filters or bulk-write precomputation:

```python
from pydantic_encryption import make_blind_index, BlindIndexMethod

index = make_blind_index("john@example.com", method=BlindIndexMethod.HMAC_SHA256, normalize_to_lowercase=True)
```

It takes the same normalization options, resolves the key from `BLIND_INDEX_SECRET_KEY` (override with `key=...`), and passes an existing `BlindIndexValue` through unchanged.

### Per-Row Salt

Pass a `salt` to fold a per-row identifier (e.g. an organization or user id) into the hash, so the same value indexes differently per row and can't be correlated by a reader without the key:

```python
a = make_blind_index("john@example.com", method=BlindIndexMethod.HMAC_SHA256, salt=org_a_id.bytes)
b = make_blind_index("john@example.com", method=BlindIndexMethod.HMAC_SHA256, salt=org_b_id.bytes)  # a != b
```

Lookups must use the same salt the row was written with; `salt=None` (default) is identical to an unsalted index. On a SQLAlchemy column, assigning a plain string stores an **unsalted** index, so salt both the write and the query with a precomputed value from `make_blind_index_value` (which uses the column's own flags):

```python
bidx = User.__table__.c.blind_index_email.type

user.blind_index_email = bidx.make_blind_index_value("john@example.com", salt=tenant_id.bytes)
session.query(User).filter(
    User.blind_index_email == bidx.make_blind_index_value("john@example.com", salt=tenant_id.bytes)
)
```

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

## Local Development

```bash
pip install -e ".[dev]"   # install with the development dependencies
pytest -v                 # run the unit tests
black .                   # format
```

The integration tier runs against a Docker-managed PostgreSQL, so Docker must be available to run the full suite.
