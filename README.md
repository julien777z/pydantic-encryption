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

## Example

```py
from pydantic_encryption import BaseModel, EncryptedModel, EncryptedField

class User(BaseModel, EncryptedModel):
    name: str
    password: EncryptedField # Encrypt this field

user = User(name="John Doe", password="123456")
print(user.password) # encrypted
```



## Choose an Encryption Method

### Evervault

If you install this package with the `evervault` extra, you can use [Evervault](https://evervault.com/) to encrypt and decrypt fields.

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

You can encrypt any field by annotating with `EncryptedField` and inheriting from `EncryptedModel`.

Alternatively, you can use `EncryptableObject` and set the `encryption` parameter to `EncryptionMode.ENCRYPT`.

```py
from pydantic_encryption import EncryptedModel, EncryptableObject, EncryptedField, BaseModel

class User(BaseModel, EncryptedModel):
    name: str
    password: EncryptedField # Encrypt this field

user = User(name="John Doe", password="123456")
print(user.password) # encrypted
print(user.name) # plaintext (untouched)

# Or use EncryptableObject directly:
class User(BaseModel, EncryptableObject, encryption=EncryptionMode.ENCRYPT):
    name: str
    password: EncryptedField

user = User(name="John Doe", password="123456")
print(user.password) # encrypted
print(user.name) # plaintext (untouched)

```

## Decryption

Similar to encryption, you can decrypt any field by annotating with `EncryptedField` and inheriting from `DecryptedModel`.

Alternatively, you can use `EncryptableObject` and set the `encryption` parameter to `EncryptionMode.DECRYPT`.

```py
from pydantic_encryption import DecryptedModel, EncryptableObject, EncryptedField, BaseModel

class UserResponse(BaseModel, DecryptedModel):
    name: str
    password: EncryptedField # Decrypt this field

user = UserResponse(**dict(user))
print(user.password) # decrypted
print(user.name) # plaintext (untouched)

# Or use EncryptableObject directly:
class UserResponse(BaseModel, EncryptableObject, encryption=EncryptionMode.DECRYPT):
    name: str
    password: EncryptedField # Decrypt this field

user = UserResponse(**dict(user))
print(user.password) # decrypted
print(user.name) # plaintext (untouched)

```

## Disable Auto-Encryption/Decryption

You can disable auto-encryption/decryption by setting the `encryption` parameter to `EncryptionMode.DISABLE_AUTO`. You will then need to call `encrypt_data()` and `decrypt_data()` manually.

```py
from pydantic_encryption import EncryptableObject, EncryptedField, BaseModel, EncryptionMode

# Set encryption to EncryptionMode.DISABLE_AUTO to disable auto-encryption/decryption
class UserResponse(BaseModel, EncryptableObject, encryption=EncryptionMode.DISABLE_AUTO):
    name: str
    password: EncryptedField

# To encrypt/decrypt, call `encrypt_data()` or `decrypt_data()`:
user = UserResponse(name="John Doe", password="ENCRYPTED_PASSWORD")

user.decrypt_data()
print(user.password) # decrypted

user.encrypt_data()
print(user.password) # encrypted
```

## BaseModel Inheritance

The encryption mode follows its children, so each child will automatically encrypt/decrypt the fields unless the encryption mode is set to `EncryptionMode.DISABLE_AUTO`.

```py
from sqlmodel import SQLModel

class UserBase(SQLModel, DecryptedModel, table=False): # SQLModel is a subclass of BaseModel
    name: str
    password: EncryptedField

class User(UserBase, table=True): # Even though we did not specify the encryption mode, it is inherited from UserBase
    pass

user = User(name="John Doe", password="ENCRYPTED_PASSWORD")
print(user.password) # decrypted
```

## Generics

Each BaseModel has an additional helpful method that will tell you its generic type.

To use generics, you must install this package with the `generics` extra: `poetry add pydantic_encryption --with generics`.

```py
from pydantic_encryption import BaseModel

class MyModel[T](BaseModel):
    value: T

model = MyModel[str](value="Hello")
print(model.get_type()) # <class 'str'>
```
