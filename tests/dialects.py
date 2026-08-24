from typing import Final

from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Dialect

#: The column types ignore the dialect they are handed, so one real dialect serves every test.
TEST_DIALECT: Final[Dialect] = postgresql.dialect()
