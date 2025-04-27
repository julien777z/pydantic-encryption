from typing import Any, Optional
from pydantic import BaseModel as PydanticBaseModel
from . import SecureModel

try:
    from generics import get_filled_type
except ImportError:
    get_filled_type = None

__all__ = ["BaseModel"]


class BaseModel(PydanticBaseModel, SecureModel):
    """Base model for encryptable models."""

    _generic_type_value: Any = None

    def model_post_init(self, context: Any, /) -> None:
        self.default_post_init()

        super().model_post_init(context)

    def get_type(self) -> Optional[type]:
        """Get the type of the model."""

        if not get_filled_type:
            raise NotImplementedError(
                "Generics are not available. Please install this package with the `generics` extra."
            )

        if self._generic_type_value:
            return self._generic_type_value

        self._generic_type_value = get_filled_type(self, BaseModel, 0)

        return self._generic_type_value
