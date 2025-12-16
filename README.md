# Encryption and Hashing Models for Pydantic

This package provides Pydantic field annotations that encrypt, decrypt, and hash field values.

## Installation

Install with [pip](https://pip.pypa.io/en/stable/):
```bash
pip install pydantic_encryption
```

Install with [Poetry](https://python-poetry.org/docs/):
```bash
poetry add pydantic_encryption
```

### Optional extras

- `aws`: AWS KMS encryption support
- `evervault`: Evervault encryption support
- `sqlalchemy`: Built-in SQLAlchemy integration
- `all`: All optional dependencies
- `dev`: Development and test dependencies

```bash
# Install with specific extras
pip install "pydantic_encryption[sqlalchemy]"
pip install "pydantic_encryption[aws]"
pip install "pydantic_encryption[all]"
```

## Features

- Encrypt and decrypt specific fields
- Hash specific fields
- Built-in SQLAlchemy integration
- Support for AWS KMS (Key Management Service) single-region
- Support for Fernet symmetric encryption and Evervault
- Support for generics

## Example

```python
from typing import Annotated
from pydantic_encryption import BaseModel, Encrypt, Hash

class User(BaseModel):
    name: str
    address: Annotated[bytes, Encrypt] # This field will be encrypted
    password: Annotated[bytes, Hash] # This field will be hashed

user = User(name="John Doe", address="123456", password="secret123")

print(user.name) # plaintext (untouched)
print(user.address) # encrypted
print(user.password) # hashed
```

## SQLAlchemy Integration

If you install this package with the `sqlalchemy` extra, you can use the built-in SQLAlchemy integration for the columns.

SQLAlchemy will automatically handle the encryption/decryption of fields with the `SQLAlchemyEncrypted` type and the hashing of fields with the `SQLAlchemyHashed` type.

When you create a new instance of the model, the fields will be encrypted and when you query the database, the fields will be decrypted.

### Example:

```python
import uuid
from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyEncrypted, SQLAlchemyHashed
from sqlmodel import SQLModel, Field
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Define our schema
class User(Base, table=True):
    __tablename__ = "users"

    username: str = Field(default=None)
    email: bytes = Field(
        default=None,
        sa_type=SQLAlchemyEncrypted(),
    )
    password: bytes = Field(
        sa_type=SQLAlchemyHashed(),
        nullable=False,
    )

# Create the database
engine = create_engine("sqlite:///:memory:")
SQLModel.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# Create a user
user = User(username="john_doe", email="john@example.com", password="secret123") # The email and password will be encrypted/hashed automatically

session.add(user)
session.commit()

# Query the user
user = session.query(User).filter_by(username="john_doe").first()

print(user.email) # decrypted
print(user.password) # hashed
```

## Choose an Encryption Method

You can choose which encryption algorithm to use by setting the `ENCRYPTION_METHOD` environment variable.

Valid values are:
- `fernet`: Fernet symmetric encryption
- `aws`: AWS KMS
- `evervault`: [Evervault](https://evervault.com/)

See [config.py](https://github.com/julien777z/pydantic-encryption/blob/main/pydantic_encryption/config.py) for the possible environment variables.

### Example:

`.env`
```env
ENCRYPTION_METHOD=aws
AWS_KMS_KEY_ARN=123
AWS_KMS_REGION=us-east-1
AWS_ACCESS_KEY_ID=123
AWS_SECRET_ACCESS_KEY=123
```

```python
from typing import Annotated
from pydantic_encryption import BaseModel, Encrypt

class User(BaseModel):
    name: str
    address: Annotated[bytes, Encrypt] # This field will be encrypted by AWS KMS
```

### Separate Encrypt/Decrypt Keys (AWS KMS)

You can use different KMS keys for encryption and decryption by setting separate ARNs:

`.env`
```env
ENCRYPTION_METHOD=aws
AWS_KMS_ENCRYPT_KEY_ARN=arn:aws:kms:us-east-1:123456789:key/encrypt-key-id
AWS_KMS_DECRYPT_KEY_ARN=arn:aws:kms:us-east-1:123456789:key/decrypt-key-id
AWS_KMS_REGION=us-east-1
AWS_ACCESS_KEY_ID=123
AWS_SECRET_ACCESS_KEY=123
```

For read-only scenarios where you only need to decrypt data, you can specify just the decrypt key:

`.env`
```env
ENCRYPTION_METHOD=aws
AWS_KMS_DECRYPT_KEY_ARN=arn:aws:kms:us-east-1:123456789:key/decrypt-key-id
AWS_KMS_REGION=us-east-1
AWS_ACCESS_KEY_ID=123
AWS_SECRET_ACCESS_KEY=123
```

**Note:** You cannot mix `AWS_KMS_KEY_ARN` with the separate key settings. Use either the global key or the separate encrypt/decrypt keys. If you specify `AWS_KMS_ENCRYPT_KEY_ARN`, you must also specify `AWS_KMS_DECRYPT_KEY_ARN`.

### Default Encryption (Fernet Symmetric Encryption)

By default, Fernet will be used for encryption and decryption.

First you need to generate an encryption key. You can use the following command:

```bash
openssl rand -base64 32
```

Then set the following environment variable or add it to your `.env` file:

```bash
ENCRYPTION_KEY=your_encryption_key
```

### Custom Encryption or Hashing

You can define your own encryption or hashing methods by subclassing `SecureModel`. `SecureModel` provides you with the utilities to handle encryption, decryption, and hashing.

`self.pending_encryption_fields`, `self.pending_decryption_fields`, and `self.pending_hash_fields` are dictionaries of field names to field values that need to be encrypted, decrypted, or hashed, i.e., fields annotated with `Encrypt`, `Decrypt`, or `Hash`.

You can override the `encrypt_data`, `decrypt_data`, and `hash_data` methods to implement your own encryption, decryption, and hashing logic. You then need to override `model_post_init` to call these methods or use the default implementation accessible via `self.default_post_init()`.

First, define a custom secure model:

```python
from typing import Any, override
from pydantic import BaseModel as PydanticBaseModel
from pydantic_encryption import SecureModel

class MySecureModel(PydanticBaseModel, SecureModel):
    @override
    def encrypt_data(self) -> None:
        # Your encryption logic here
        pass

    @override
    def decrypt_data(self) -> None:
        # Your decryption logic here
        pass

    @override
    def hash_data(self) -> None:
        # Your hashing logic here
        pass

    @override
    def model_post_init(self, context: Any, /) -> None:
        # Either define your own logic, for example:

        # if not self._disable:
        #     if self.pending_decryption_fields:
        #         self.decrypt_data()

        #     if self.pending_encryption_fields:
        #         self.encrypt_data()

        #     if self.pending_hash_fields:
        #         self.hash_data()

        # Or use the default logic:
        self.default_post_init()

        super().model_post_init(context)
```

Then use it:

```python
from typing import Annotated
from pydantic import BaseModel # Here, we don't use the BaseModel provided by the library, but the native one from Pydantic
from pydantic_encryption import Encrypt

class MyModel(BaseModel, MySecureModel):
    username: str
    address: Annotated[bytes, Encrypt]

model = MyModel(username="john_doe", address="123456")
print(model.address) # encrypted
```

## Encryption

You can encrypt any field by using the `Encrypt` annotation with `Annotated` and inheriting from `BaseModel`.

```python
from typing import Annotated
from pydantic_encryption import Encrypt, BaseModel

class User(BaseModel):
    name: str
    address: Annotated[bytes, Encrypt] # This field will be encrypted

user = User(name="John Doe", address="123456")
print(user.address) # encrypted
print(user.name) # plaintext (untouched)
```

The fields marked with `Encrypt` are automatically encrypted during model initialization.

## Decryption

Similar to encryption, you can decrypt any field by using the `Decrypt` annotation with `Annotated` and inheriting from `BaseModel`.

```python
from typing import Annotated
from pydantic_encryption import Decrypt, BaseModel

class UserResponse(BaseModel):
    name: str
    address: Annotated[bytes, Decrypt] # This field will be decrypted

user = UserResponse(**user_data) # encrypted value
print(user.address) # decrypted
print(user.name) # plaintext (untouched)
```

Fields marked with `Decrypt` are automatically decrypted during model initialization.

Note: if you use `SQLAlchemyEncrypted`, then the value will be decrypted automatically when you query the database.


## Hashing

You can hash sensitive data like passwords by using the `Hash` annotation.

```python
from typing import Annotated
from pydantic_encryption import Hash, BaseModel

class User(BaseModel):
    username: str
    password: Annotated[bytes, Hash] # This field will be hashed

user = User(username="john_doe", password="secret123")
print(user.password) # hashed value
```

Fields marked with `Hash` are automatically hashed using Argon2 during model initialization.

## Disable Auto Processing

You can disable automatic encryption/decryption/hashing by setting `disable` to `True` in the class definition.

```python
from typing import Annotated
from pydantic_encryption import Encrypt, BaseModel

class UserResponse(BaseModel, disable=True):
    name: str
    address: Annotated[bytes, Encrypt]

# To encrypt/decrypt/hash, call the respective methods manually:
user = UserResponse(name="John Doe", address="123 Main St")

# Manual encryption
user.encrypt_data()
print(user.address) # encrypted

# Or user.decrypt_data() to decrypt and user.hash_data() to hash
```

## Generics

Each BaseModel has an additional helpful method that will tell you its generic type.

```py
from pydantic_encryption import BaseModel

class MyModel[T](BaseModel):
    value: T

model = MyModel[str](value="Hello")
print(model.get_type()) # <class 'str'>
```

## Run Tests

Install [Poetry](https://python-poetry.org/docs/) and run:

```bash
poetry install --all-extras
poetry run pytest -v
```

## Roadmap

This is an early development version. I am considering the following features:

- [ ] Add optional support for other encryption providers beyond Evervault
- [x] Add support for AWS KMS and other key management services
- [ ] Native encryption via PostgreSQL and other databases
- [ ] Specifying encryption key per table or row instead of globally

## Feature Requests

If you have any feature requests, please open an issue.
