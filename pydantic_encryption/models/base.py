from super_model import SuperModel
from . import SecureModel

__all__ = ["BaseModel"]


class BaseModel(SuperModel, SecureModel):
    """Base model for encryptable models."""
