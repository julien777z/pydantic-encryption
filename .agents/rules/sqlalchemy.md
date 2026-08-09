---
description: Use SQLAlchemy ORM/core query builders and shared table helpers instead of manual SQL strings.
alwaysApply: true
---

# SQLAlchemy Rules

## Table Definitions

- Tables use SQLAlchemy 2.0 declarative models and inherit from the project's shared declarative base classes.
- Define `__tablename__` and `__table_args__` explicitly for each table.
- Use `Mapped[T]` + `mapped_column(...)` for all columns.
- Prefer schema-qualified foreign keys with typed configuration values (for example, `ForeignKey(f"{CONFIG.DATABASE_SCHEMA_NAME}.resources.id")`).

```python
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from myapp.core.config import CONFIG

from . import Base

if TYPE_CHECKING:
    from .authors import Author


class Post(Base):
    __tablename__ = "posts"
    __table_args__ = (
        UniqueConstraint("blog_id", "slug", name="uq_post_blog_slug"),
        {"schema": CONFIG.DATABASE_SCHEMA_NAME},
    )

    author_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey(f"{CONFIG.DATABASE_SCHEMA_NAME}.authors.id"),
        index=True,
    )
    author: Mapped["Author"] = relationship(lazy="selectin")
```

## Relationships

- Use `TYPE_CHECKING` imports and string annotations to avoid circular imports.
- Default relationship loading should be `lazy="selectin"` to avoid N+1 query patterns.
- Keep relationship configuration explicit (`back_populates`, `cascade`, `foreign_keys`) when needed.

## Query Methods

Prefer the project's shared ORM helpers for common reads, pagination, counts, inserts, upserts, and updates when they exist.

- **Important**: when the project's persistence helpers treat bare `None` as omitted, use the project's explicit SQL-NULL sentinel to persist `NULL` on nullable columns.
- Use a single-row update path when changing one loaded entity and a bulk-update path only when one statement intentionally updates multiple matching rows.
- Do not refresh an entity merely to repair stale state after a persistence helper that already updates and flushes the loaded instance.
- Do not manually mutate ORM entity attributes and flush when the repository provides a persistence helper for that operation.
- Avoid manual `session.execute(...)` query construction in service code for standard CRUD/filter flows (including hand-built `select(...).join(...).where(...)` statements).
- Prefer adding or extending reusable query helpers on the project's shared ORM base when a new operation is needed (for example, join-aware lookup helpers) and then consume that helper from services.
- Use direct/manual `session.execute(...)` only for advanced operations that are not practical to express via existing shared helpers.

## Session and Transaction Boundaries

- Route handlers should depend on the project's database-session dependency.
- Route handlers must not perform ORM reads or writes or build response models from ORM rows inline; that data access belongs in a service function that returns the response model.
- Service functions should accept `AsyncSession` and never create their own DB sessions.
- Do not call `commit()` inside service functions; request/session lifecycle owns transaction completion.

## Postgres Types and Time Handling

- Use PostgreSQL-specific types where needed (`JSONB`, `ARRAY`, SQLAlchemy `Enum`).
- Use timezone-aware timestamp columns (`DateTime(timezone=True)`) for event/timeline fields.
- Use UTC datetimes for application timestamps (`datetime.now(UTC)`).

## Gotchas

- Do not use SQLModel-only APIs (`table=True`, `Field(...)`, SQLModel `Relationship(...)`) in this codebase.
- All service surfaces should centralize transaction lifecycle in their database-session dependency.
- When adding filters/upserts, align with existing `where` clause patterns and class helper methods instead of bespoke query flows.
