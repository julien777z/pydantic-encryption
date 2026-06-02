from __future__ import annotations

import threading
from typing import Callable

from pydantic_encryption.types import BlindIndexMethod, EncryptionMethod

encryption_backends: dict[EncryptionMethod, type] = {}
encryption_factories: dict[EncryptionMethod, Callable[[], type]] = {}
blind_index_backends: dict[BlindIndexMethod, type] = {}

registry_lock = threading.Lock()


def register_encryption_backend(method: EncryptionMethod, cls: type) -> None:
    encryption_backends[method] = cls


def register_encryption_backend_lazy(method: EncryptionMethod, factory: Callable[[], type]) -> None:
    encryption_factories[method] = factory


def get_encryption_backend(method: EncryptionMethod) -> type:
    if method in encryption_backends:
        return encryption_backends[method]
    with registry_lock:
        if method in encryption_backends:
            return encryption_backends[method]
        factory = encryption_factories.get(method)
        if factory is not None:
            # Invoke first; only remove from factories on success so a failing
            # factory (e.g. missing optional dep) stays retryable and surfaces
            # its real ImportError instead of a generic "no backend" ValueError.
            cls = factory()
            encryption_backends[method] = cls
            del encryption_factories[method]
            return cls
    raise ValueError(f"No encryption backend registered for {method!r}")


def register_blind_index_backend(method: BlindIndexMethod, cls: type) -> None:
    blind_index_backends[method] = cls


def get_blind_index_backend(method: BlindIndexMethod) -> type:
    if method in blind_index_backends:
        return blind_index_backends[method]
    raise ValueError(f"No blind index backend registered for {method!r}")


# Register lazy-loaded backends for optional dependencies
def load_aws_adapter():
    from pydantic_encryption.adapters.encryption.aws import AWSAdapter

    return AWSAdapter


register_encryption_backend_lazy(EncryptionMethod.AWS, load_aws_adapter)
