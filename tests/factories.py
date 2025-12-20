from polyfactory.factories.pydantic_factory import ModelFactory

from tests.models.users import User, UserDecrypt, UserDisabledEncryption


class UserFactory(ModelFactory[User]):
    __model__ = User

    @classmethod
    def address(cls) -> str:
        return cls.__faker__.address()

    @classmethod
    def password(cls) -> str:
        return cls.__faker__.password()


class UserDecryptFactory(ModelFactory[UserDecrypt]):
    __model__ = UserDecrypt

    @classmethod
    def address(cls) -> bytes:
        return cls.__faker__.address().encode("utf-8")

    @classmethod
    def password(cls) -> str:
        return cls.__faker__.password()


class UserDisabledFactory(ModelFactory[UserDisabledEncryption]):
    __model__ = UserDisabledEncryption

    @classmethod
    def address(cls) -> str:
        return cls.__faker__.address()

    @classmethod
    def password(cls) -> str:
        return cls.__faker__.password()
