from typing import Any

from super_model import SuperModel

from . import SecureModel

__all__ = ["BaseModel"]


class BaseModel(SuperModel, SecureModel):
    """Base model for encryptable models."""

    def model_post_init(self, context: Any, /) -> None:
        self.default_post_init()

        super().model_post_init(context)
