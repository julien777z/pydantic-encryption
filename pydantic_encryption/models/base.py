from typing import Any, override
from pydantic import BaseModel as PydanticBaseModel
from .encryption import EncryptableObject

try:
    from generics import get_filled_type
except ImportError:
    get_filled_type = None

__all__ = ["BaseModel"]


class BaseModel(PydanticBaseModel, EncryptableObject):
    """Base model for encryptable models."""

    _generic_type_value: Any = None

    @override
    def model_post_init(self, context: Any, /) -> None:
        if not self._disable:
            if self.pending_decryption_fields:
                self.decrypt_data()

            if self.pending_encryption_fields:
                self.encrypt_data()

        super().model_post_init(context)

    def get_type(self) -> type | None:
        """Get the type of the model."""

        if not get_filled_type:
            raise NotImplementedError(
                "Generics are not available. Please install this package with the `generics` extra."
            )

        if self._generic_type_value:
            return self._generic_type_value

        self._generic_type_value = get_filled_type(self, BaseModel, 0)

        return self._generic_type_value
