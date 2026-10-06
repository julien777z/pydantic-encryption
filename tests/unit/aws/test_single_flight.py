import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest
from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidTag

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from tests.factories import User
from tests.kms import KMS_TEST_CONTEXT
from tests.models.kms import ControlledKMSClient, FakeSyncKMSClient, SlowFakeKMS


class TestSingleFlight:
    """Test that threads racing a cold cache share one KMS call between them."""

    def test_racing_threads_mint_one_key(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that concurrent sync encrypts on a cold cache generate one key, not one each."""

        slow = SlowFakeKMS()
        monkeypatch.setattr(AWSAdapter, "_sync_client", slow)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(
                pool.map(
                    lambda index: AWSAdapter.encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT),
                    range(8),
                )
            )

        assert len(slow.generate_calls) == 1

    def test_threads_racing_a_cold_key_unwrap_it_once(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that concurrent sync decrypts of one cold data key unwrap it once, not once each."""

        slow = SlowFakeKMS()
        monkeypatch.setattr(AWSAdapter, "_sync_client", slow)
        ciphertexts = [
            AWSAdapter.encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT) for index in range(8)
        ]

        with ThreadPoolExecutor(max_workers=8) as pool:
            decrypted = list(
                pool.map(
                    lambda ciphertext: AWSAdapter.decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT),
                    ciphertexts,
                )
            )

        assert decrypted == [f"value-{index}" for index in range(8)]
        assert len(slow.decrypt_calls) == 1

    @pytest.mark.asyncio
    async def test_distinct_cold_keys_overlap(
        self, controlled_kms: ControlledKMSClient, users_batch: list[User], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that unrelated cold keys reach KMS concurrently and all decrypt correctly."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_USES", 1)
        values = [user.username for user in users_batch[:3]]
        ciphertexts = [
            await AWSAdapter.async_encrypt(value, associated_data=KMS_TEST_CONTEXT) for value in values
        ]
        tasks = [
            asyncio.create_task(AWSAdapter.async_decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT))
            for ciphertext in ciphertexts
        ]

        try:
            assert await asyncio.to_thread(controlled_kms.wait_for_calls, len(tasks))
        finally:
            controlled_kms.release.set()
            results = await asyncio.gather(*tasks, return_exceptions=True)

        assert results == values
        assert controlled_kms.calls == len(values)
        assert AWSAdapter.unwrapping == {}

    @pytest.mark.asyncio
    async def test_shared_failure_allows_retry(
        self, controlled_kms: ControlledKMSClient, kms_failure: ClientError, user: User
    ) -> None:
        """Test that one failed KMS reply reaches all waiters and a later call retries."""

        ciphertext = await AWSAdapter.async_encrypt(user.username, associated_data=KMS_TEST_CONTEXT)
        controlled_kms.error = kms_failure
        tasks = [
            asyncio.create_task(AWSAdapter.async_decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT))
            for _ in range(3)
        ]

        try:
            assert await asyncio.to_thread(controlled_kms.wait_for_waiters, len(tasks) - 1)
        finally:
            controlled_kms.release.set()
            failures = await asyncio.gather(*tasks, return_exceptions=True)

        assert all(failure is kms_failure for failure in failures)
        assert controlled_kms.calls == 1
        assert AWSAdapter.unwrapping == {}

        controlled_kms.error = None

        assert await AWSAdapter.async_decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT) == user.username
        assert controlled_kms.calls == 2

    @pytest.mark.asyncio
    async def test_concurrent_misses_respect_capacity(
        self, controlled_kms: ControlledKMSClient, users_batch: list[User], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that distinct unwraps wait for capacity independently of cached-key retention."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_USES", 1)
        monkeypatch.setattr(settings, "AWS_KMS_MAX_IN_FLIGHT_UNWRAPS", 2)
        monkeypatch.setattr(settings, "AWS_KMS_UNWRAPPED_KEY_CACHE_SIZE", 1)
        values = [user.username for user in users_batch[:3]]
        ciphertexts = [
            await AWSAdapter.async_encrypt(value, associated_data=KMS_TEST_CONTEXT) for value in values
        ]
        tasks = [
            asyncio.create_task(AWSAdapter.async_decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT))
            for ciphertext in ciphertexts
        ]

        try:
            assert await asyncio.to_thread(controlled_kms.wait_for_calls, 2)
            assert await asyncio.to_thread(controlled_kms.wait_for_admission_waiter)

            assert controlled_kms.calls == 2
            assert len(AWSAdapter.unwrapping) == 2
        finally:
            controlled_kms.release.set()
            results = await asyncio.gather(*tasks, return_exceptions=True)

        assert results == values
        assert controlled_kms.calls == len(values)
        assert len(AWSAdapter.unwrapped_keys) == 1
        assert AWSAdapter.unwrapping == {}

    @pytest.mark.asyncio
    async def test_cancelling_owner_keeps_shared_unwrap_alive(
        self, controlled_kms: ControlledKMSClient, user: User
    ) -> None:
        """Test that cancelling one caller preserves its KMS context and another caller's reply."""

        ciphertext = await AWSAdapter.async_encrypt(user.username, associated_data=KMS_TEST_CONTEXT)
        context_token = controlled_kms.invocation_context.set(user.payload)
        owner = asyncio.create_task(AWSAdapter.async_decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT))
        tasks = [owner]

        try:
            assert await asyncio.to_thread(controlled_kms.wait_for_calls, 1)

            follower = asyncio.create_task(
                AWSAdapter.async_decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT)
            )
            tasks.append(follower)

            assert await asyncio.to_thread(controlled_kms.wait_for_waiters, 1)
            owner.cancel()

            with pytest.raises(asyncio.CancelledError):
                await owner

            assert not follower.done()
            assert controlled_kms.calls == 1
        finally:
            controlled_kms.release.set()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            controlled_kms.invocation_context.reset(context_token)

        assert isinstance(results[0], asyncio.CancelledError)
        assert results[1] == user.username
        assert controlled_kms.observed_contexts == [user.payload]
        assert AWSAdapter.unwrapping == {}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("source", [b"", KMS_TEST_CONTEXT], ids=["unbound", "foreign"])
    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    async def test_shared_key_retains_each_callers_authenticated_context(
        self, controlled_kms: ControlledKMSClient, user: User, source: bytes, asynchronous: bool
    ) -> None:
        """Test that a shared KMS reply never authenticates a caller using the wrong context."""

        ciphertext = await AWSAdapter.async_encrypt(user.username, associated_data=source)
        tasks = [
            asyncio.create_task(
                AWSAdapter.async_decrypt(ciphertext, associated_data=context)
                if asynchronous
                else asyncio.to_thread(AWSAdapter.decrypt, ciphertext, associated_data=context)
            )
            for context in (source, user.payload)
        ]

        try:
            assert await asyncio.to_thread(controlled_kms.wait_for_waiters, 1)
        finally:
            controlled_kms.release.set()
            results = await asyncio.gather(*tasks, return_exceptions=True)

        assert results[0] == user.username
        assert isinstance(results[1], InvalidTag)
        assert controlled_kms.calls == 1
        assert AWSAdapter.unwrapping == {}
