from polyfactory.factories.pydantic_factory import ModelFactory

from tests.models.users import User, UserNameFixture


class UserFactory(ModelFactory[User]):
    __model__ = User

    @classmethod
    def address(cls) -> str:
        return cls.__faker__.address()

    @classmethod
    def password(cls) -> str:
        return cls.__faker__.password()


class UserNameFactory(ModelFactory[UserNameFixture]):
    """Factory for UserNameFixture with faker-backed name + bytes payload."""

    __model__ = UserNameFixture

    @classmethod
    def first_name(cls) -> str:
        return cls.__faker__.first_name()

    @classmethod
    def last_name(cls) -> str:
        return cls.__faker__.last_name()

    @classmethod
    def payload(cls) -> bytes:
        return cls.__faker__.binary(length=16)
