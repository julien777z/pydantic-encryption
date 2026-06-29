# SQLAlchemy Rules

## Table Definitions

- Tables use SQLAlchemy 2.0 declarative models and inherit from project base classes (`Base`, `RecordsBase`, `TaxableEntityBase`) built on `BaseTable`.
- Define `__tablename__` and `__table_args__` explicitly for each table.
- Use `Mapped[T]` + `mapped_column(...)` for all columns.
- Prefer schema-qualified foreign keys with config values (for example, `ForeignKey(f"{CONFIG.DATABASE_SCHEMA_NAME}.users.id")`).

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

Use the shared `BaseTable` helpers for common operations:

- `get_one(session, where=...)` - Get single record
- `get_all(session, where=..., offset=..., limit=...)` - Get paginated records with total count
- `insert(session, {...})` - Insert new record and flush
- `upsert(session, {...}, where=...)` - Insert or update
- `bulk_update(session, where=..., values=...)` - Update **all rows matching `where`** in one SQL statement (multi-row updates only).
- `await entity.update(session, **fields)` - Update **this loaded row** from keyword fields, attach, and flush (single-row path; async).
- `query_count(session, where=...)` - Count records
- **Important**: `upsert` and instance `update` strip bare `None` values via `filter_values`. Use `NullValue` from `vaultgig_common.database.tables` to explicitly persist SQL `NULL` on nullable columns.
- Do **not** use `bulk_update` with a primary-key/`id` predicate just to change one row when you already hold that ORM instance; use `await entity.update(...)` instead.
- Do **not** call `session.refresh` after persisting through `BaseTable` to reconcile ORM state; `await entity.update(...)` updates the instance and flushes.
- Never manually mutate ORM entity attributes and call `session.flush()`; use the BaseTable methods above instead.
- Avoid manual `session.execute(...)` query construction in service code for standard CRUD/filter flows (including hand-built `select(...).join(...).where(...)` statements).
- Prefer adding or extending reusable query helpers in `vaultgig_common`/`BaseTable` when a new operation is needed (for example, join-aware lookup helpers) and then consume that helper from services.
- Use direct/manual `session.execute(...)` only for advanced operations that are not practical to express via existing shared helpers.

## Session and Transaction Boundaries

- Route handlers should depend on `DatabaseSession`.
- Service functions should accept `AsyncSession` and never create their own DB sessions.
- Do not call `commit()` inside service functions; request/session lifecycle owns transaction completion.

## Postgres Types and Time Handling

- Use PostgreSQL-specific types where needed (`JSONB`, `ARRAY`, SQLAlchemy `Enum`).
- Use timezone-aware timestamp columns (`DateTime(timezone=True)`) for event/timeline fields.
- Use UTC datetimes for application timestamps (`datetime.now(UTC)`).

## Gotchas

- Do not use SQLModel-only APIs (`table=True`, `Field(...)`, SQLModel `Relationship(...)`) in this codebase.
- API and Records services use different session wrappers, but both centralize transaction lifecycle in the DB session dependency.
- When adding filters/upserts, align with existing `where` clause patterns and class helper methods instead of bespoke query flows.
