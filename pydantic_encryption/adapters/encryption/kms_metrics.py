import hashlib
import json
import logging
import threading
import time
from enum import Enum
from typing import Any, Final, TypedDict

from aws_encryption_sdk.caches.local import LocalCryptoMaterialsCache
from aws_encryption_sdk.exceptions import CacheKeyError

logger = logging.getLogger(__name__)

KMS_ROUND_TRIP_LOG_PREFIX: Final[str] = "kms_round_trip "
KEY_REFERENCE_LENGTH: Final[int] = 8


class KmsRoundTrip(Enum):
    """The KMS calls a materials cache miss forces."""

    GENERATE = "generate"
    UNWRAP = "unwrap"


class KmsRoundTripRecord(TypedDict):
    """One KMS round trip, as the reported log line carries it."""

    round_trip: str
    key_reference: str
    elapsed_seconds: float
    concurrent_round_trips: int


def key_reference(cache_key: bytes) -> str:
    """Return a short non-reversible reference to a materials cache key."""

    return hashlib.sha256(cache_key).hexdigest()[:KEY_REFERENCE_LENGTH]


class MeteredMaterialsCache(LocalCryptoMaterialsCache):
    """Materials cache reporting each KMS round trip a miss forces, with its concurrency."""

    def __init__(self, capacity: int) -> None:
        """Start with no round trip in flight."""

        super().__init__(capacity=capacity)  # pyright: ignore[reportCallIssue]

        self.pending = threading.local()
        self.gauge_lock = threading.Lock()
        self.round_trips_in_flight = 0

    def start_round_trip(self) -> None:
        """Record that this thread's cache miss has sent it to KMS."""

        if getattr(self.pending, "started_at", None) is None:
            with self.gauge_lock:
                self.round_trips_in_flight += 1

        self.pending.started_at = time.perf_counter()

    def finish_round_trip(self, round_trip: KmsRoundTrip, cache_key: bytes) -> None:
        """Report the round trip this thread's miss forced, once its materials land in the cache."""

        started_at = getattr(self.pending, "started_at", None)

        if started_at is None:
            return

        self.pending.started_at = None
        elapsed_seconds = time.perf_counter() - started_at

        with self.gauge_lock:
            concurrent_round_trips = self.round_trips_in_flight
            self.round_trips_in_flight -= 1

        record = KmsRoundTripRecord(
            round_trip=round_trip.value,
            key_reference=key_reference(cache_key),
            elapsed_seconds=elapsed_seconds,
            concurrent_round_trips=concurrent_round_trips,
        )

        logger.info("%s%s", KMS_ROUND_TRIP_LOG_PREFIX, json.dumps(record))

    def get_encryption_materials(self, cache_key: bytes, plaintext_length: int) -> Any:
        """Return cached encryption materials, noting the KMS round trip a miss forces."""

        try:
            return super().get_encryption_materials(cache_key, plaintext_length)
        except CacheKeyError:
            self.start_round_trip()

            raise

    def put_encryption_materials(
        self,
        cache_key: bytes,
        encryption_materials: Any,
        plaintext_length: int,
        entry_hints: Any = None,
    ) -> Any:
        """Store newly generated encryption materials and report the round trip that minted them."""

        entry = super().put_encryption_materials(
            cache_key, encryption_materials, plaintext_length, entry_hints
        )

        self.finish_round_trip(KmsRoundTrip.GENERATE, cache_key)

        return entry

    def get_decryption_materials(self, cache_key: bytes) -> Any:
        """Return cached decryption materials, noting the KMS round trip a miss forces."""

        try:
            return super().get_decryption_materials(cache_key)
        except CacheKeyError:
            self.start_round_trip()

            raise

    def put_decryption_materials(self, cache_key: bytes, decryption_materials: Any) -> Any:
        """Store newly unwrapped decryption materials and report the round trip that unwrapped them."""

        entry = super().put_decryption_materials(cache_key, decryption_materials)

        self.finish_round_trip(KmsRoundTrip.UNWRAP, cache_key)

        return entry
