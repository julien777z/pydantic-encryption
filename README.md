# pydantic-secure

Field-level encryption, hashing, and blind indexing for Pydantic models with SQLAlchemy integration.

## Installation

```bash
pip install pydantic-secure
```

### Optional extras

```bash
pip install "pydantic-secure[sqlalchemy]"  # SQLAlchemy integration
pip install "pydantic-secure[aws]"         # AWS KMS encryption
pip install "pydantic-secure[all]"         # All optional dependencies
```

## Quick Start

```python
from typing import Annotated
from pydantic_secure import BaseModel, Encrypted, Hashed

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

Separate encrypt/decrypt keys are supported for key rotation or read-only scenarios:

```bash
AWS_KMS_ENCRYPT_KEY_ARN=arn:aws:kms:...encrypt-key
AWS_KMS_DECRYPT_KEY_ARN=arn:aws:kms:...decrypt-key
```

### Model-Level Config

Override encryption settings per model instead of relying on environment variables:

```python
from pydantic_secure import BaseModel, Encrypted, EncryptionMethod
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
from pydantic_secure import BaseModel, BlindIndex, BlindIndexMethod

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

Install with `pip install "pydantic-secure[sqlalchemy]"`.

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session

from pydantic_secure import (
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
from pydantic_secure import SQLAlchemyPGEncryptedArray

tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray(), nullable=True)
```

Each element is individually encrypted. Requires PostgreSQL.

## Custom Encryption or Hashing

Subclass `SecureModel` to implement your own logic:

```python
from pydantic import BaseModel as PydanticBaseModel
from pydantic_secure import SecureModel

class MySecureModel(PydanticBaseModel, SecureModel):
    def encrypt_data(self) -> None:
        # your encryption logic
        pass

    def model_post_init(self, context, /):
        self.default_post_init()
        super().model_post_init(context)
```

## Run Tests

```bash
pip install -e ".[dev]"
pytest -v
```
