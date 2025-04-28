class EncryptableString(str):
    """A string that can be encrypted."""

    _is_encrypted: bool = False

    def __new__(cls, value, **kwargs):
        obj = super().__new__(cls, value)

        for key, val in kwargs.items():
            setattr(obj, key, val)

        return obj

    @property
    def is_encrypted(self) -> bool:
        """Return True if the string is encrypted, False otherwise."""

        return self._is_encrypted

    @is_encrypted.setter
    def is_encrypted(self, value: bool) -> None:
        self._is_encrypted = value


class HashableString(str):
    """A string that can be hashed."""

    _is_hashed: bool = False

    def __new__(cls, value, **kwargs):
        obj = super().__new__(cls, value)

        for key, val in kwargs.items():
            setattr(obj, key, val)

        return obj

    @property
    def is_hashed(self) -> bool:
        """Return True if the string is hashed, False otherwise."""

        return self._is_hashed

    @is_hashed.setter
    def is_hashed(self, value: bool) -> None:
        self._is_hashed = value
