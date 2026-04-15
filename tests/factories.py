from polyfactory.factories.pydantic_factory import ModelFactory

from tests.models.users import User


class UserFactory(ModelFactory[User]):
    __model__ = User

    @classmethod
    def address(cls) -> str:
        return cls.__faker__.address()

    @classmethod
    def password(cls) -> str:
        return cls.__faker__.password()
