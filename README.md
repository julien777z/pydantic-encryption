# Encryption and Hashing Models for Pydantic

Field-level encryption, decryption, hashing, and blind indexing for Pydantic models with SQLAlchemy integration.

## Installation

```bash
pip install pydantic_encryption
```

### Optional extras

```bash
pip install "pydantic_encryption[sqlalchemy]"  # SQLAlchemy integration
pip install "pydantic_encryption[aws]"          # AWS KMS encryption
pip install "pydantic_encryption[all]"          # All optional dependencies
```

## Quick Start

```python
from typing import Annotated
from pydantic_encryption import BaseModel, Encrypt, Hash

class User(BaseModel):
    name: str
    address: Annotated[bytes, Encrypt]
    password: Annotated[bytes, Hash]

user = User(name="John Doe", address="123456", password="secret123")

print(user.name)      # plaintext
print(user.address)   # encrypted
print(user.password)  # hashed
```

Fields marked with `Encrypt` are encrypted and fields marked with `Hash` are hashed during model initialization.

To decrypt, use the `Decrypt` annotation:

```python
from pydantic_encryption import Decrypt, BaseModel

class UserResponse(BaseModel):
    address: Annotated[str, Decrypt]

user = UserResponse(address=encrypted_bytes)
print(user.address)  # decrypted
```

## Encryption Methods

Set the encryption method via environment variable:

```bash
ENCRYPTION_METHOD=fernet   # Fernet symmetric encryption (requires ENCRYPTION_KEY)
ENCRYPTION_METHOD=aws      # AWS KMS (requires AWS_KMS_KEY_ARN, AWS_KMS_REGION, etc.)
ENCRYPTION_METHOD=evervault # Evervault
```

There is no default — you must explicitly set `ENCRYPTION_METHOD` if using `Encrypt`/`Decrypt` fields.

### Fernet Setup

```bash
# Generate a key
openssl rand -base64 32

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

See [config.py](https://github.com/julien777z/pydantic-encryption/blob/main/pydantic_encryption/config.py) for all environment variables.

## SQLAlchemy Integration

Install with `pip install "pydantic_encryption[sqlalchemy]"`.

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session

from pydantic_encryption.integrations.sqlalchemy import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyHashed,
    SQLAlchemyBlindIndexValue,
)
from pydantic_encryption.types import BlindIndexMethod


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str]
    email: Mapped[bytes] = mapped_column(SQLAlchemyEncryptedValue())
    password: Mapped[bytes] = mapped_column(SQLAlchemyHashed())
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

`SQLAlchemyBlindIndexValue` supports the same normalization options as `BlindIndex`:

```python
blind_index_email: Mapped[bytes] = mapped_column(
    SQLAlchemyBlindIndexValue(
        BlindIndexMethod.HMAC_SHA256,
        normalize_to_lowercase=True,
        strip_whitespace=True,
    )
)
```

### Supported Types

`SQLAlchemyEncryptedValue` preserves the Python type of your data:

`str`, `bytes`, `bool`, `int`, `float`, `Decimal`, `UUID`, `date`, `datetime`, `time`, `timedelta`

### Array Support (PostgreSQL)

```python
from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyPGEncryptedArray

tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray(), nullable=True)
```

Each element is individually encrypted. Requires PostgreSQL.

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

You can normalize values before hashing to ensure consistent lookups:

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

## Disable Auto-Processing

```python
class UserResponse(BaseModel, disable=True):
    address: Annotated[bytes, Encrypt]

user = UserResponse(address="123 Main St")
user.encrypt_data()  # manual encryption
```

## Custom Encryption or Hashing

Subclass `SecureModel` to implement your own logic:

```python
from pydantic import BaseModel as PydanticBaseModel
from pydantic_encryption import SecureModel

class MySecureModel(PydanticBaseModel, SecureModel):
    def encrypt_data(self) -> None:
        # your encryption logic
        pass

    def model_post_init(self, context, /):
        self.default_post_init()
        super().model_post_init(context)
```

## Generics

```python
from pydantic_encryption import BaseModel

class MyModel[T](BaseModel):
    value: T

model = MyModel[str](value="Hello")
print(model.get_type())  # <class 'str'>
```

## Run Tests

```bash
poetry install --all-extras
poetry run pytest -v
```
