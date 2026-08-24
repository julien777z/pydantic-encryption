import asyncio

import pytest
from sqlalchemy.orm import DeclarativeBase, Mapped, configure_mappers, mapped_column

from pydantic_encryption.integrations.sqlalchemy import DeferredDecryptMixin, decrypt_values
from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyPGEncryptedArray,
    decrypt_cell,
    encrypt_cell,
)
from pydantic_encryption.integrations.sqlalchemy.serialization import decode_value, encode_value
from pydantic_encryption.types import EncryptedValue, FieldBinding, FieldBindingError
from tests.dialects import TEST_DIALECT
from tests.mapped_columns import column_binding, column_type, encrypt_as_column


class BindingBase(DeclarativeBase):
    """Isolated declarative base for the field-binding tests."""


class BindingPerson(BindingBase, DeferredDecryptMixin):
    """Mapped class with two encrypted columns a value must not travel between."""

    __tablename__ = "_binding_person"
    __table_args__ = {"schema": "secure"}

    id: Mapped[int] = mapped_column(primary_key=True)
    ssn: Mapped[str | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    nickname: Mapped[str | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    aliases: Mapped[list[str] | None] = mapped_column(
        SQLAlchemyPGEncryptedArray(), nullable=True, default=None
    )


class BindingNeighbour(BindingBase, DeferredDecryptMixin):
    """A second table whose same-named column must not read the first table's ciphertext."""

    __tablename__ = "_binding_neighbour"
    __table_args__ = {"schema": "secure"}

    id: Mapped[int] = mapped_column(primary_key=True)
    ssn: Mapped[str | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)


class TestColumnsCarryTheirOwnBinding:
    """Test that a mapped encrypted column knows the table and column it stores values for."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_binding_names_the_schema_qualified_table_and_column(self):
        """Test that a column's binding identifies it uniquely across schemas."""

        assert column_binding(BindingPerson, "ssn") == FieldBinding(
            table="secure._binding_person", column="ssn"
        )

    def test_sibling_columns_carry_distinct_bindings(self):
        """Test that two encrypted columns on one table do not share a binding."""

        assert column_binding(BindingPerson, "ssn") != column_binding(BindingPerson, "nickname")

    def test_same_column_name_on_another_table_carries_a_distinct_binding(self):
        """Test that the table is part of the binding, not just the column name."""

        assert column_binding(BindingPerson, "ssn") != column_binding(BindingNeighbour, "ssn")

    def test_a_standalone_type_is_unbound(self):
        """Test that a type never attached to a table binds nothing."""

        assert SQLAlchemyEncryptedValue().binding is None

    def test_binding_rejects_a_name_carrying_the_envelope_delimiter(self):
        """Test that a name which would corrupt the envelope is refused when the binding is built."""

        with pytest.raises(ValueError, match="cannot contain"):
            FieldBinding(table="schema:table", column="ssn")


class RenamedBase(DeclarativeBase):
    """Isolated declarative base for the pinned-binding tests."""


class RenamedPerson(RenamedBase, DeferredDecryptMixin):
    """Mapped class whose column was renamed while its stored values keep their original binding."""

    __tablename__ = "_binding_person"
    __table_args__ = {"schema": "secure"}

    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(binding_name="legal_full_name"), nullable=True, default=None
    )


class TestAPinnedBindingSurvivesAColumnRename:
    """Test that a renamed column can keep reading the values its former name wrote."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_the_pinned_name_replaces_the_column_key(self):
        """Test that the binding follows the pinned name rather than the current column."""

        assert column_binding(RenamedPerson, "full_name") == FieldBinding(
            table="secure._binding_person", column="legal_full_name"
        )

    def test_it_reads_a_value_written_under_the_former_name(self):
        """Test that data written before the rename still decrypts through the renamed column."""

        written_before_the_rename = encrypt_cell(
            "Sam Rivers", FieldBinding(table="secure._binding_person", column="legal_full_name")
        )

        assert written_before_the_rename is not None

        person = RenamedPerson(id=1, full_name=written_before_the_rename)

        asyncio.run(person.decrypt())

        assert person.full_name == "Sam Rivers"

    def test_it_still_refuses_another_field(self):
        """Test that pinning a name narrows the binding to that field rather than disabling the check."""

        ciphertext = encrypt_as_column(BindingPerson, "nickname", "Sam")

        with pytest.raises(FieldBindingError, match="legal_full_name"):
            decrypt_cell(ciphertext, column_binding(RenamedPerson, "full_name"))


class TestCiphertextIsRejectedAsAnotherField:
    """Test that a ciphertext only decrypts as the field it was encrypted for."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_a_sibling_column_refuses_it(self):
        """Test that a value written for one column cannot be read back through another."""

        ciphertext = encrypt_as_column(BindingPerson, "ssn", "555-00-1234")

        with pytest.raises(FieldBindingError, match="_binding_person.nickname"):
            decrypt_cell(ciphertext, column_binding(BindingPerson, "nickname"))

    def test_the_same_column_on_another_table_refuses_it(self):
        """Test that an identically named column on another table cannot read it."""

        ciphertext = encrypt_as_column(BindingPerson, "ssn", "555-00-1234")

        with pytest.raises(FieldBindingError, match="_binding_neighbour.ssn"):
            decrypt_cell(ciphertext, column_binding(BindingNeighbour, "ssn"))

    def test_an_unbound_reader_refuses_it(self):
        """Test that moving a column's ciphertext onto a context-free path does not disclose it."""

        ciphertext = encrypt_as_column(BindingPerson, "ssn", "555-00-1234")

        with pytest.raises(FieldBindingError, match="no field"):
            decrypt_cell(ciphertext, None)

    def test_a_bound_reader_refuses_an_unbound_ciphertext(self):
        """Test that a value carrying no binding cannot satisfy a column that requires one."""

        unbound = SQLAlchemyEncryptedValue().process_bind_param("555-00-1234", TEST_DIALECT)

        assert unbound is not None

        with pytest.raises(FieldBindingError, match="_binding_person.ssn"):
            decrypt_cell(unbound, column_binding(BindingPerson, "ssn"))

    def test_its_own_column_reads_it(self):
        """Test that the column the value was written for still reads it back unchanged."""

        ciphertext = encrypt_as_column(BindingPerson, "ssn", "555-00-1234")

        assert decrypt_cell(ciphertext, column_binding(BindingPerson, "ssn")) == "555-00-1234"


class TestBatchedDrainCarriesTheBinding:
    """Test that the batched decrypt path binds each cell to the column it was loaded from."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_the_drain_decrypts_every_column_against_its_own_binding(self):
        """Test that a row with several encrypted columns drains without a binding mismatch."""

        person = BindingPerson(
            id=1,
            ssn=encrypt_as_column(BindingPerson, "ssn", "555-00-1234"),
            nickname=encrypt_as_column(BindingPerson, "nickname", "Sam"),
        )

        asyncio.run(person.decrypt())

        assert person.ssn == "555-00-1234"
        assert person.nickname == "Sam"

    def test_the_drain_rejects_a_cell_transplanted_from_a_sibling_column(self):
        """Test that a row carrying another column's ciphertext fails the drain rather than reading it."""

        person = BindingPerson(id=1, nickname=encrypt_as_column(BindingPerson, "ssn", "555-00-1234"))

        with pytest.raises(FieldBindingError):
            asyncio.run(person.decrypt())


class TestArrayElementsBindToTheirColumn:
    """Test that each element of an encrypted array carries the array column's own binding."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_elements_round_trip_through_their_own_column(self):
        """Test that array elements written by a column are read back by that same column."""

        stored = column_type(BindingPerson, "aliases").process_bind_param(["Ali", "Sam"], TEST_DIALECT)

        assert stored is not None

        person = BindingPerson(id=1, aliases=[EncryptedValue(element) for element in stored])

        asyncio.run(person.decrypt())

        assert person.aliases == ["Ali", "Sam"]

    def test_an_element_is_refused_by_a_scalar_column(self):
        """Test that an array element cannot be read back through a scalar column on the same table."""

        stored = column_type(BindingPerson, "aliases").process_bind_param(["Ali"], TEST_DIALECT)

        assert stored is not None

        with pytest.raises(FieldBindingError, match="_binding_person.ssn"):
            decrypt_cell(stored[0], column_binding(BindingPerson, "ssn"))


class TestFlatDecryptNamesItsField:
    """Test that the flat decrypt helper enforces the binding its caller names."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_it_decrypts_values_written_for_the_named_column(self):
        """Test that a column's own ciphertexts decrypt when that column is named."""

        values = [encrypt_as_column(BindingPerson, "ssn", f"555-00-000{index}") for index in range(3)]

        binding = column_binding(BindingPerson, "ssn")

        result = asyncio.run(decrypt_values((value, binding) for value in values))

        assert result == ["555-00-0000", "555-00-0001", "555-00-0002"]

    def test_it_refuses_values_written_for_a_different_column(self):
        """Test that naming the wrong column fails rather than disclosing the value."""

        values = [encrypt_as_column(BindingPerson, "ssn", "555-00-1234")]
        wrong_binding = column_binding(BindingPerson, "nickname")

        with pytest.raises(FieldBindingError):
            asyncio.run(decrypt_values((value, wrong_binding) for value in values))


class TestEnvelopeCarriesTheBinding:
    """Test the envelope that stores a value's binding alongside its type and data."""

    def test_an_unbound_envelope_round_trips(self):
        """Test that a value encoded with no binding decodes with no binding."""

        assert decode_value(encode_value("hello", None), None) == "hello"

    def test_a_bound_envelope_round_trips(self):
        """Test that a value encoded for a field decodes when that same field is named."""

        binding = FieldBinding(table="secure.people", column="ssn")

        assert decode_value(encode_value("hello", binding), binding) == "hello"

    def test_the_binding_is_not_stored_in_the_clear_beside_the_data(self):
        """Test that the envelope keeps the value itself out of its binding segment."""

        binding = FieldBinding(table="secure.people", column="ssn")
        envelope = encode_value("555-00-1234", binding)

        assert envelope.startswith("v2:secure.people.ssn:")
