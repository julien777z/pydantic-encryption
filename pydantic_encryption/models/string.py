class NormalizedString(str):
    """A string that normalizes all input."""

    def __new__(cls, value, **kwargs):
        match value:
            case bytes():
                try:
                    value = value.decode("utf-8")
                except UnicodeDecodeError:
                    value = str(value)
            case str():
                pass
            case _:
                raise ValueError(f"Unsupported type: {type(value)}")

        obj = super().__new__(cls, value)

        for key, val in kwargs.items():
            setattr(obj, key, val)

        return obj


class EncryptableString(NormalizedString):
    """A string that can be encrypted."""

    encrypted: bool = False


class HashableString(NormalizedString):
    """A string that can be hashed."""

    hashed: bool = False
