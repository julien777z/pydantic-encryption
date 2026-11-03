import asyncio
from unittest.mock import patch

import pytest
from cryptography.fernet import InvalidToken
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.integrations.sqlalchemy import decrypt_pending_fields, decrypt_rows, decrypt_values
from pydantic_encryption.integrations.sqlalchemy.bulk import decrypt_rows_sync
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY
from pydantic_encryption.types import EncryptedValue
from tests.factories import SampleRecord
from tests.unit.test_sqlalchemy.tables import (
    Member,
    Organization,
    PayloadRow,
    PlainSecretRow,
    RenamedColumnRow,
    SecretRow,
)
from tests.unit.test_sqlalchemy.utils import RecordingAsyncSession, collected_cells, encrypt_through_column
from tests.unit.utils import ASYNC_PATHS, call_path


@pytest.mark.asyncio
class TestBulk:
    """Test the bulk paths that decrypt deferred cells across rows, values and loaded relationships."""

    async def test_rows_decrypt_across_columns(self, samples: list[SampleRecord]):
        """Test that every named column of every row is decrypted, leaving empty cells empty."""

        rows = [Member.from_sample(sample) for sample in samples] + [Member.sealed(None, None)]

        await decrypt_rows(rows, "label", Member.caption)

        assert [(row.label, row.caption) for row in rows] == [
            *((sample.label, sample.caption) for sample in samples),
            (None, None),
        ]

    async def test_rows_decrypt_named_columns_only(self, samples: list[SampleRecord]):
        """Test that decrypting one column leaves the others sealed."""

        rows = [Member.from_sample(sample) for sample in samples]

        await decrypt_rows(rows, "label")

        assert [sa_inspect(row).dict["label"] for row in rows] == [sample.label for sample in samples]
        assert all(isinstance(sa_inspect(row).dict["caption"], EncryptedValue) for row in rows)

    async def test_rows_decrypt_once_per_row(self, sample: SampleRecord, other_sample: SampleRecord):
        """Test that one decrypt call is issued per sealed cell, skipping cells already decrypted."""

        rows = [PayloadRow.from_sample(sample), PayloadRow.from_sample(other_sample)]
        original_decrypt = FernetAdapter.async_decrypt

        await decrypt_rows(rows[:1], "payload")

        with patch.object(FernetAdapter, "async_decrypt", side_effect=original_decrypt) as counted:
            await decrypt_rows(rows, "payload")

        assert counted.call_count == 1
        assert [sa_inspect(row).dict["payload"] for row in rows] == [sample.payload, other_sample.payload]

    @ASYNC_PATHS
    async def test_moved_ciphertext_refused(self, asynchronous: bool, sample: SampleRecord):
        """Test that a cell holding another column's ciphertext raises, once every other cell has opened."""

        moved = Member(caption=encrypt_through_column(Member.__table__.c.label, sample.label))
        intact = Member.sealed(None, sample.caption)

        with pytest.raises(BaseExceptionGroup) as raised:
            await call_path(asynchronous, decrypt_rows_sync, decrypt_rows, [moved, intact], "caption")

        assert raised.group_contains(InvalidToken)
        assert isinstance(sa_inspect(moved).dict["caption"], EncryptedValue)
        assert sa_inspect(intact).dict["caption"] == sample.caption

    @ASYNC_PATHS
    async def test_no_columns_leaves_rows_sealed(self, asynchronous: bool):
        """Test that naming no column leaves the rows sealed."""

        row = SecretRow.sealed("secret data", id=1)

        await call_path(asynchronous, decrypt_rows_sync, decrypt_rows, [row])

        assert isinstance(sa_inspect(row).dict["secret"], EncryptedValue)

    async def test_values_decrypt_in_place(self):
        """Test that ciphertexts decrypt in place while other values keep their positions."""

        values = [
            encrypt_through_column(Member.__table__.c.label, "first"),
            None,
            42,
            "plain",
            encrypt_through_column(Member.__table__.c.label, "second"),
        ]

        assert await decrypt_values(values, context=Member.label) == ["first", None, 42, "plain", "second"]

    @pytest.mark.parametrize("name", ["draft-payloads", b"draft-payloads"], ids=["text", "bytes"])
    async def test_values_decrypt_under_declared_name(self, name: str | bytes):
        """Test that a column type declared with a name, as text or bytes, has its ciphertexts open under it."""

        values = [SQLAlchemyEncryptedValue(name).encrypt_cell("draft")]

        assert await decrypt_values(values, context="draft-payloads") == ["draft"]

    @pytest.mark.parametrize("values", [[], [None, "plain", 42]], ids=["empty", "no-ciphertext"])
    async def test_values_without_ciphertext_returned(self, values: list[object]):
        """Test that a list holding no ciphertext comes back as it was."""

        assert await decrypt_values(values, context=Member.label) == values

    async def test_plain_column_context_refused(self):
        """Test that naming a plain column as the context raises rather than binding nothing."""

        values = [encrypt_through_column(Member.__table__.c.label, "first")]

        with pytest.raises(ValueError, match="does not encrypt its values"):
            await decrypt_values(values, context=Member.id)

    @pytest.mark.parametrize("members", [None, []], ids=["none", "empty"])
    async def test_mixin_decrypts_nothing_quietly(self, members: list[Member] | None):
        """Test that decrypting no entities completes without raising."""

        assert await Member.decrypt_many(members) is None

    async def test_mixin_decrypts_instance(self, sample: SampleRecord):
        """Test that decrypting one instance restores every column and returns it."""

        member = Member.from_sample(sample)

        assert await member.decrypt() is member
        assert (member.label, member.caption) == (sample.label, sample.caption)

    async def test_mixin_decrypts_many(self, samples: list[SampleRecord]):
        """Test that decrypting many instances, from any iterable, restores each one's columns."""

        members = [Member.from_sample(sample) for sample in samples]

        await Member.decrypt_many(member for member in members)

        assert [(m.label, m.caption) for m in members] == [
            (sample.label, sample.caption) for sample in samples
        ]

    async def test_mixin_walks_loaded_relationships(self, sample: SampleRecord):
        """Test that decrypting a parent decrypts the loaded children it holds."""

        organization = Organization(id=1, name="sample organization")
        member = Member.from_sample(sample)
        organization.members = [member]

        await organization.decrypt()

        assert member.label == sample.label

    async def test_renamed_column_decrypted(self, sqlite_session: Session):
        """Test that an attribute stored under another column name is decrypted in bulk."""

        sqlite_session.add(RenamedColumnRow(id=1, secret="secret data"))
        sqlite_session.commit()
        sqlite_session.expunge_all()

        row = sqlite_session.get(RenamedColumnRow, 1)

        await RenamedColumnRow.decrypt_many([row])

        assert sa_inspect(row).dict["secret"] == "secret data"

    async def test_decrypted_cells_stay_clean(self, sample: SampleRecord):
        """Test that decrypting a cell does not mark it dirty for the next flush."""

        member = Member.from_sample(sample)
        state = sa_inspect(member)
        state._commit_all(state.dict)

        await Member.decrypt_many([member])

        assert sa_inspect(member).dict["label"] == sample.label
        assert "label" not in state.committed_state

    @pytest.mark.parametrize("entities", [[None], [object()]], ids=["absent", "unmapped"])
    async def test_walk_skips_entities_without_cells(self, entities: list[object]):
        """Test that an absent or unmapped entity carries no cells to collect."""

        assert collected_cells(entities) == {}

    async def test_walk_skips_columns_off_deferred_path(self):
        """Test that an encrypted column whose class never deferred reads carries no cell to collect."""

        row = PlainSecretRow(
            id=1, secret=encrypt_through_column(PlainSecretRow.__table__.c.secret, "secret data")
        )

        assert collected_cells(row) == {}

    async def test_walk_skips_decrypted_cells(self, sample: SampleRecord):
        """Test that a cell already decrypted is not collected again."""

        row = PayloadRow.from_sample(sample)

        await PayloadRow.decrypt_many([row])

        assert collected_cells(row) == {}

    async def test_walk_follows_loaded_relationships(self, sample: SampleRecord):
        """Test that the walk collects cells through loaded relationships, in either direction."""

        organization = Organization(
            id=1, secret=encrypt_through_column(Organization.__table__.c.secret, "secret")
        )
        member = Member.from_sample(sample)
        organization.members = [member]

        expected = {(Organization, "secret"), (Member, "label"), (Member, "caption")}

        assert set(collected_cells(organization)) == expected
        assert set(collected_cells(member)) == expected

    async def test_walk_skips_empty_relationships(self, sample: SampleRecord):
        """Test that a relationship holding nothing, or loaded as absent, is not walked into."""

        organization = Organization(
            id=1, secret=encrypt_through_column(Organization.__table__.c.secret, "secret"), members=[]
        )
        member = Member.sealed(sample.label, None, organization=None)

        assert list(collected_cells(organization)) == [(Organization, "secret")]
        assert list(collected_cells(member)) == [(Member, "label")]

    async def test_pending_fields_drained(self, sample: SampleRecord):
        """Test that draining a session decrypts the pending cells of every class and empties its bucket."""

        member = Member.from_sample(sample)
        payload = PayloadRow.from_sample(sample)
        session = RecordingAsyncSession(in_transaction=False, pending=[member, payload])

        await decrypt_pending_fields(session)

        assert sa_inspect(member).dict["label"] == sample.label
        assert sa_inspect(payload).dict["payload"] == sample.payload
        assert PENDING_DECRYPT_KEY not in session.info

    async def test_drain_without_bucket_adds_none(self):
        """Test that draining a session with no bucket leaves it without one."""

        session = AsyncSession()

        await decrypt_pending_fields(session)

        assert PENDING_DECRYPT_KEY not in session.info

    async def test_drain_decrypts_classes_concurrently(self, sample: SampleRecord):
        """Test that the drain keeps decrypts of different classes in flight together."""

        rows = [Member.from_sample(sample), PayloadRow.from_sample(sample)]
        session = RecordingAsyncSession(in_transaction=False, pending=rows)
        original_decrypt = FernetAdapter.decrypt
        live_overlap = 0
        peak_overlap = 0

        async def overlapping_decrypt(
            ciphertext: bytes, *, key: str | None = None, associated_data: bytes
        ) -> str:
            """Track how many decrypts are in flight before decrypting."""

            nonlocal live_overlap, peak_overlap

            live_overlap += 1
            peak_overlap = max(peak_overlap, live_overlap)

            try:
                await asyncio.sleep(0)

                return original_decrypt(ciphertext, key=key, associated_data=associated_data)
            finally:
                live_overlap -= 1

        with patch.object(FernetAdapter, "async_decrypt", side_effect=overlapping_decrypt):
            await decrypt_pending_fields(session)

        assert sa_inspect(rows[0]).dict["label"] == sample.label
        assert peak_overlap >= 2
