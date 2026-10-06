from __future__ import annotations

import threading
from collections.abc import Callable

from pydantic_encryption.adapters.base import BlindIndexAdapter, EncryptionAdapter
from pydantic_encryption.types import BlindIndexMethod, EncryptionMethod

encryption_backends: dict[EncryptionMethod, type[EncryptionAdapter]] = {}
encryption_factories: dict[EncryptionMethod, Callable[[], type[EncryptionAdapter]]] = {}
blind_index_backends: dict[BlindIndexMethod, type[BlindIndexAdapter]] = {}

registry_lock: threading.Lock = threading.Lock()


def register_encryption_backend(method: EncryptionMethod, cls: type[EncryptionAdapter]) -> None:
    """Register the encryption adapter serving ``method``."""

    encryption_backends[method] = cls


def register_encryption_backend_lazy(
    method: EncryptionMethod, factory: Callable[[], type[EncryptionAdapter]]
) -> None:
    """Register a factory that imports the encryption adapter serving ``method`` on first use."""

    encryption_factories[method] = factory


def get_encryption_backend(method: EncryptionMethod) -> type[EncryptionAdapter]:
    """Return the encryption adapter serving ``method``."""

    if method in encryption_backends:
        return encryption_backends[method]

    with registry_lock:
        if method in encryption_backends:
            return encryption_backends[method]

        factory = encryption_factories.get(method)
        if factory is not None:
            cls = factory()
            encryption_backends[method] = cls
            del encryption_factories[method]

            return cls

    raise ValueError(f"No encryption backend registered for {method!r}")


def register_blind_index_backend(method: BlindIndexMethod, cls: type[BlindIndexAdapter]) -> None:
    """Register the blind index adapter serving ``method``."""

    blind_index_backends[method] = cls


def get_blind_index_backend(method: BlindIndexMethod) -> type[BlindIndexAdapter]:
    """Return the blind index adapter serving ``method``."""

    if method in blind_index_backends:
        return blind_index_backends[method]

    raise ValueError(f"No blind index backend registered for {method!r}")


def load_aws_adapter() -> type[EncryptionAdapter]:
    """Import the AWS KMS adapter, which needs the ``aws`` extra."""

    from pydantic_encryption.adapters.encryption.aws import AWSAdapter

    return AWSAdapter


register_encryption_backend_lazy(EncryptionMethod.AWS, load_aws_adapter)
