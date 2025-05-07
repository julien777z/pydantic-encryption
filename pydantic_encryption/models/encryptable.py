class NormalizeToBytes(bytes):
    """Normalize a value to bytes."""

    def __new__(cls, value: str | bytes):
        if isinstance(value, str):
            value = value.encode("utf-8")

        return super().__new__(cls, value)


class NormalizeToString(str):
    """Normalize a value to string."""

    def __new__(cls, value: str | bytes):
        if isinstance(value, bytes):
            value = value.decode("utf-8")

        return super().__new__(cls, value)


class EncryptedValue(NormalizeToBytes):
    encrypted: bool = True


class DecryptedValue(NormalizeToString):
    encrypted: bool = False


class HashedValue(NormalizeToBytes):
    hashed: bool = True
