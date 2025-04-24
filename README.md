# Encryption models for Pydantic

This package provides Pydantic field types that encrypt and decrypt the field values.

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
from pydantic_encryption import BaseModel, EncryptField

class User(BaseModel):
    name: str
    password: EncryptField # This field will be encrypted

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

You can define your own encryption and decryption methods by subclassing `EncryptableObject`.

`EncryptableObject` provides you with the utilities to handle encryption and decryption.

`self.pending_encryption_fields` and `self.pending_decryption_fields` are dictionaries of field names to field values that need to be encrypted or decrypted, i.e., fields annotated with `EncryptField` or `DecryptField`.

You can override the `encrypt_data` and `decrypt_data` methods to implement your own encryption and decryption logic.

You then need to override `model_post_init` to call `self.encrypt_data()` and/or `self.decrypt_data()`.

First, define a custom encryptable object:

```py
from typing import override
from pydantic_encryption import EncryptableObject

class MyEncryptableObject(EncryptableObject):
    @override
    def encrypt_data(self) -> None:
        # Your encryption logic here
        pass

    @override
    def decrypt_data(self) -> None:
        # Your decryption logic here
        pass

    @override
    def model_post_init(self, context: Any, /) -> None:
        if not self._disable:
            if self.pending_decryption_fields:
                self.decrypt_data()

            if self.pending_encryption_fields:
                self.encrypt_data()

        super().model_post_init(context)
```

Then use it:

```py
from pydantic import BaseModel # Here, we don't use the BaseModel provided by the library, but the native one from Pydantic
from pydantic_encryption import EncryptField

class MyModel(BaseModel, MyEncryptableObject):
    username: str
    password: EncryptField

model = MyModel(username="john_doe", password="123456")
print(model.password) # encrypted
```

## Encryption

You can encrypt any field by annotating with `EncryptField` and inheriting from `EncryptableObject`.

```py
from pydantic_encryption import EncryptableObject, EncryptField, BaseModel

class User(BaseModel):
    name: str
    password: EncryptField # This field will be encrypted

user = User(name="John Doe", password="123456")
print(user.password) # encrypted
print(user.name) # plaintext (untouched)
```

## Decryption

Similar to encryption, you can decrypt any field by annotating with `DecryptField` and inheriting from `EncryptableObject`.

```py
from pydantic_encryption import EncryptableObject, DecryptField, BaseModel

class User(BaseModel, EncryptableObject):
    name: str
    password: DecryptField # This field will be decrypted

user = User(name="John Doe", password="123456")
print(user.password) # encrypted
print(user.name) # plaintext (untouched)

```


## Disable Auto-Encryption/Decryption

You can disable auto-encryption/decryption by setting `disable` to `True` in the class definition.

```py
from pydantic_encryption import EncryptableObject, EncryptField, BaseModel

class UserResponse(BaseModel, EncryptableObject, disable=True):
    name: str
    password: EncryptField

# To encrypt/decrypt, call `encrypt_data()` or `decrypt_data()`:
user = UserResponse(name="John Doe", password="ENCRYPTED_PASSWORD")

user.decrypt_data()
print(user.password) # decrypted

user.encrypt_data()
print(user.password) # encrypted
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

## Run Tests

```bash
poetry install --with test
poetry run coverage run -m pytest -v -s
```
