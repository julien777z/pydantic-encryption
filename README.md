# Encryption models for Pydantic

This package provides Pydantic models that encrypt and decrypt fields.

## Installation

Install [Poetry](https://python-poetry.org/) if you haven't already.

Install this package with the `evervault` and `generics` extras:
```bash
poetry add pydantic_encryption --with evervault,generics
```

Install this package without extras:
```bash
poetry add pydantic_encryption
```

## Features

- Encrypt and decrypt fields
- Support for BaseModel inheritance
- Support for generics


## Choose an Encryption Method

### Evervault

If you install this package with the `evervault` extra, you can use Evervault to encrypt and decrypt fields.

You need to set the following environment variables or add them to your `.env` file:

```bash
EVERVAULT_APP_ID=your_app_id
EVERVAULT_API_KEY=your_api_key
EVERVAULT_ENCRYPTION_ROLE=your_encryption_role
```

### Custom Encryption

You can define your own encryption and decryption functions by subclassing `EncryptableObject`.

```py
from typing import override
from pydantic_encryption import EncryptableObject, EncryptedModel, EncryptionMode
from pydantic import BaseModel # We are making our own BaseModel

class MyEncryptableObject(EncryptableObject):
    @override
    def encrypt_data(self) -> None:
        # Your encryption logic here
        pass

    @override
    def decrypt_data(self) -> None:
        # Your decryption logic here
        pass

class MyModel(BaseModel, EncryptedModel, MyEncryptableObject):
    pass
```

## Encryption

```py
from pydantic_encryption import EncryptedModel, EncryptableObject, EncryptedField, BaseModel

# Encrypt any field by annotating with EncryptedField and inheriting from EncryptedModel
class User(BaseModel, EncryptedModel):
    name: str
    password: EncryptedField[str]

user = User(name="John Doe", password="123456")
print(user.password) # encrypted
print(user.name) # plaintext (untouched)

# Or use EncryptableObject directly:
class User(BaseModel, EncryptableObject, encryption=EncryptionMode.ENCRYPT):
    name: str
    password: EncryptedField[str]

user = User(name="John Doe", password="123456")
print(user.password) # encrypted
print(user.name) # plaintext (untouched)

```

## Decryption

```py
from pydantic_encryption import DecryptedModel, EncryptableObject, EncryptedField, BaseModel

# Decrypt any field by annotating with EncryptedField and inheriting from DecryptedModel
class UserResponse(BaseModel, DecryptedModel):
    name: str
    password: EncryptedField[str]

user = UserResponse(**dict(user))
print(user.password) # decrypted
print(user.name) # plaintext (untouched)

# Or use EncryptableObject directly:
class UserResponse(BaseModel, EncryptableObject, encryption=EncryptionMode.DECRYPT):
    name: str
    password: EncryptedField[str]

user = UserResponse(**dict(user))
print(user.password) # decrypted
print(user.name) # plaintext (untouched)

```

## BaseModel inheritance

```py
# Imagine you have multiple nested BaseModels:

from sqlmodel import SQLModel

class UserBase(SQLModel, DecryptedModel, table=False): # SQLModel is a subclass of BaseModel
    name: str
    password: EncryptedField[str]

class User(UserBase, table=True):
    pass

user = User(name="John Doe", password="ENCRYPTED_PASSWORD")
print(user.password) # decrypted
```

## Generics

To use generics, you must install this package with the `generics` extra: `poetry add pydantic_encryption --with generics`.

```py
from pydantic_encryption import BaseModel

class MyModel[T](BaseModel):
    value: T

model = MyModel[str](value="Hello")
print(model.get_type()) # <class 'str'>
```
