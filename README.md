# Encryption and hashing models for Pydantic

This package provides Pydantic field annotations that encrypt, decrypt, and hash field values.

## Installation

Install with Pip:
```bash
pip install pydantic_encryption
```

### Optional extras

- `generics`: Support for generics

## Features

- Encrypt and decrypt specific fields
- Support for Fernet symmetric encryption and Evervault
- Hash specific fields
- Support for generics

## Example

```python
from pydantic_encryption import BaseModel, Encrypt, Hash, Annotated

class User(BaseModel):
    name: str
    address: Annotated[str, Encrypt] # This field will be encrypted
    password: Annotated[str, Hash] # This field will be hashed

user = User(name="John Doe", address="123456", password="secret123")

print(user.name) # plaintext (untouched)
print(user.address) # encrypted
print(user.password) # hashed
```

## Choose an Encryption Method

You can choose which encryption method to use by setting the `use_encryption_method` parameter in the class definition.

### Example:

```python
from typing import Annotated
from pydantic_encryption import EncryptionMethod, BaseModel, Encrypt

class User(BaseModel, use_encryption_method=EncryptionMethod.EVERVAULT):
    name: str
    address: Annotated[str, Encrypt] # This field will be encrypted by Evervault
```

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

### Evervault

You can optionally use [Evervault](https://evervault.com/) to encrypt and decrypt fields.

Set the `use_encryption_method` parameter to `EncryptionMethod.EVERVAULT`.

You need to set the following environment variables or add them to your `.env` file:

```bash
EVERVAULT_APP_ID=your_app_id
EVERVAULT_API_KEY=your_api_key
EVERVAULT_ENCRYPTION_ROLE=your_encryption_role
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
    address: Annotated[str, Encrypt]

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
    address: Annotated[str, Encrypt] # This field will be encrypted

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
    address: Annotated[str, Decrypt] # This field will be decrypted

user = UserResponse(**user_data) # encrypted value
print(user.address) # decrypted
print(user.name) # plaintext (untouched)
```

Fields marked with `Decrypt` are automatically decrypted during model initialization.


## Hashing

You can hash sensitive data like passwords by using the `Hash` annotation.

```python
from typing import Annotated
from pydantic_encryption import Hash, BaseModel

class User(BaseModel):
    username: str
    password: Annotated[str, Hash] # This field will be hashed

user = User(username="john_doe", password="secret123")
print(user.password) # hashed value
```

Fields marked with `Hash` are automatically hashed using bcrypt during model initialization.

## Disable Auto Processing

You can disable automatic encryption/decryption/hashing by setting `disable` to `True` in the class definition.

```python
from typing import Annotated
from pydantic_encryption import Encrypt, BaseModel

class UserResponse(BaseModel, disable=True):
    name: str
    address: Annotated[str, Encrypt]

# To encrypt/decrypt/hash, call the respective methods manually:
user = UserResponse(name="John Doe", address="123 Main St")

# Manual encryption
user.encrypt_data()
print(user.address) # encrypted

# Or user.decrypt_data() to decrypt and user.hash_data() to hash
```

## Generics

Each BaseModel has an additional helpful method that will tell you its generic type.

To use generics, you must install this package with the `generics` extra: `pip install pydantic_encryption[generics]`.

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
poetry install --with test
poetry run coverage run -m pytest -v -s
```

## Roadmap

This is an early development version. I am considering the following features:

- [ ] Add optional support for other encryption providers beyond Evervault
- [ ] Add support for AWS KMS and other key management services
- [ ] Native encryption via PostgreSQL and other databases
- [ ] Specifying encryption key per table or row instead of globally

## Feature Requests

If you have any feature requests, please open an issue.
