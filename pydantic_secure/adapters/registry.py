from __future__ import annotations

from typing import Callable

from pydantic_secure.types import BlindIndexMethod, EncryptionMethod

_encryption_backends: dict[EncryptionMethod, type] = {}
_encryption_factories: dict[EncryptionMethod, Callable[[], type]] = {}

_blind_index_backends: dict[BlindIndexMethod, type] = {}


def register_encryption_backend(method: EncryptionMethod, cls: type) -> None:
    _encryption_backends[method] = cls


def register_encryption_backend_lazy(method: EncryptionMethod, factory: Callable[[], type]) -> None:
    _encryption_factories[method] = factory


def get_encryption_backend(method: EncryptionMethod) -> type:
    if method in _encryption_backends:
        return _encryption_backends[method]
    if method in _encryption_factories:
        cls = _encryption_factories[method]()
        _encryption_backends[method] = cls
        del _encryption_factories[method]
        return cls
    raise ValueError(f"No encryption backend registered for {method!r}")


def register_blind_index_backend(method: BlindIndexMethod, cls: type) -> None:
    _blind_index_backends[method] = cls


def get_blind_index_backend(method: BlindIndexMethod) -> type:
    if method in _blind_index_backends:
        return _blind_index_backends[method]
    raise ValueError(f"No blind index backend registered for {method!r}")


# Register lazy-loaded backends for optional dependencies
def _load_aws_adapter():
    from pydantic_secure.adapters.encryption.aws import AWSAdapter

    return AWSAdapter


register_encryption_backend_lazy(EncryptionMethod.AWS, _load_aws_adapter)
