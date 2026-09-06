---
name: test-fixture
description: Organize, add, or change pytest tests using canonical fixtures, factories, shared test utilities, concise cases, parametrization, honest doubles, and regression-proof validation. Use for Python tests, test data, fixtures, factories, builders, mocks, test placement, or test setup.
---

# Test Fixture

Build tests from the repository's canonical test surfaces, keep them beside the source concern they
exercise, and prove that new coverage detects the regression it claims to prevent.

## Dependencies

Read the repository's product-constraints skill when the skill listing declares one, found by its
description rather than assumed by name. It says how broad the fix for an issue encountered while
tracing a test surface is; without one, fix what the focused pass can finish.

## Find The Canonical Test Data

Before adding a value, fixture, factory, or builder, discover the current suite's fixture mechanism
and shared fixture locations, configured factory mechanism, repository-wide shared test utilities,
and analogous tests in sibling services or projects. Read sibling tests for placement, naming,
setup, parametrization, and assertion conventions, but never import from a sibling test suite. Move
genuinely shared support to the nearest common test owner instead.

Use the value from the fixture or factory that owns the domain object. When that canonical surface
lacks a field the test needs, extend it and update its consumers instead of hard-coding the value,
adding a parallel fixture, or constructing a second representation in the test.

Test data speaks the domain of the source its suite mirrors, or none. Draw names, values,
fixtures, and scenarios from the nouns that source already uses; where it is a library with no
domain of its own, invent neutral placeholders. A consumer's table, schema, model, or product name
never enters a library's tests, the application's nouns and packages never enter the tests of a
generic package beside it, and a setting the application does not serve never enters the
application's tests: each describes a system the source does not own. The vocabulary of a third
party the source integrates with is its own.

Literal case values are allowed inside `pytest.mark.parametrize`; keep shared fixture-backed context
outside the parameter table. A literal outside parametrization is not a substitute for a fixture
value that exists or belongs on the canonical fixture.

A helper has three possible homes, and how many readers it has decides which. A trivial predicate
or formatter that one module reads may stay in that module. A helper one suite reads goes in that
suite's `utils` module. A helper more than one suite reads goes in the tier's `utils/` package,
under a topic-named module. Reaching into a sibling suite instead is what turns one suite's helper
directory into an unofficial shared home, and once a tier has several of those, nothing
distinguishes real setup from a workaround someone parked next to a failing test.

The suite's canonical root fixtures are the roots of test data. Put reusable subordinate identity,
report, form, billing, and business data on those typed fixture models instead of creating parallel
fixtures, and read nested values off them directly. Keep variant-only fields on typed subclasses of
the root, and select a variant through one aggregate creator with a typed selector rather than a
parallel creator per variant.

## Mirror Source Ownership

Discover the repository's source roots, test roots, suite tiers, and existing ownership conventions.
An ordinary test mirrors the source path for the concern it exercises after removing the source and
test roots and test-classification segments such as unit or integration. The paths need not be
character-for-character identical; their ownership hierarchy must be recognizable in both trees.

Before placing or moving a test, compare analogous sibling service tests and their corresponding
source owners. Apply explicit repository guidance first. Otherwise prefer the layout that most
directly mirrors source ownership, using the majority pattern among analogous sibling service tests
as corroborating evidence. Existing sibling tests are evidence, not authority. Preserve a different
layout only when a real ownership or boundary difference explains it; legacy placement alone is not
a reason. If equally valid patterns remain, present the concrete choice to the user instead of moving
tests arbitrarily or adding another variation.

Test-owned structures may follow the testing concern rather than a production path:

- fixture, factory, shared-case, utility, snapshot, and harness packages;
- integration or end-to-end flows that deliberately span several source modules;
- a behavior folder that replaces one heavily tested source module with several focused test
  modules, one class each, named for the behavior each covers rather than for the class.

Place a cross-module test at the nearest shared source owner.

A second class in one module is a second subject: the module name promises one thing while the
file covers several, and a reader scrolling for the class they want passes everything else on the
way. The folder that replaces it already carries the source file's name, so repeating that name in
every child module is noise; each child is named for the behavior its one class covers.

## Prefer Parametrized Cases

Before adding a test, inspect the existing tests for the same behavior. When setup, exercised flow,
and assertions are the same and only inputs or expected outcomes differ, extend or convert the
existing test with `pytest.mark.parametrize` instead of adding another test method. Give cases
readable IDs, parametrize with readable lists or tuples and convert to a set inside the test when
the subject needs one, and keep shared fixture context outside the parameter table.

Add a separate test when its setup, control flow, asserted behavior, or failure meaning materially
differs. Do not force unrelated scenarios into one parameter table merely because they call the same
function.

```python
@pytest.mark.parametrize(
    ("postal_code", "expected_region"),
    [
        ("03301", "NH"),
        ("90001", "CA"),
    ],
)
def test_lookup_region(postal_code: str, expected_region: str) -> None:
    result = lookup_postal_region(postal_code)

    assert result is not None
    assert result.region == expected_region
```

Derive the values a case ranges over from the production type that already declares them rather
than restating them: parametrize over the enum's own members, because a hand-written list of its
values is a second copy that no rename will reach.

A case is a scenario the tests invent: a table of inputs and their expected outcomes, a stored
`pytest.mark.parametrize` decorator, the `ids` naming those scenarios, and any descriptor model the
scenarios are built from. A case shared by more than one test module lives in a `test_cases`
package, never in a general-purpose `utils.py`. Put the package at the level its consumers span, the
way `conftest.py` already sits at shared boundaries, with a module per domain and an `__init__.py`
that re-exports what tests import. A table only one module reads stays in that module: promote it
when a second module needs it, not before. Name a case for the domain it addresses rather than its
position in the module it came from, since the name has to stand on its own once the definition no
longer sits above its tests.

An inventory of production symbols a test iterates is not a case, even though it reaches
`parametrize` the same way. A registry of the endpoint classes to check, the models a contract
covers, or the config files that must all behave alike describes the subject under test rather than
a scenario, so it stays in the module that tests it.

Treat a test name as a short case label, not a sentence. State only what distinguishes the case from
the subject already named by its module and class; remove filler and repeated subject words. Follow a
configured repository limit when one exists. Otherwise aim for four or five words after `test_` and
never exceed eight. The docstring carries the full sentence: the condition, the expected result, and
why it matters.

When a name is over, that is the order to cut in: the articles and connective prose first — `a`,
`the`, `that`, `it`, `its` — then every noun the module or the class already states. What is left is
the behavior under test, which is the only part the name owes a reader. A name already inside the
limit is finished: an article that survives in a short name is not a violation to go hunting for,
and stripping one to reach a word count nothing was asking for can cost the reader the grammar that
made the name scan.

```python
class TestRedeemCoupon:
    """Test redeeming a coupon against its expiry and usage limits."""

    # Bad: the name restates the whole assertion, and the docstring repeats it
    def test_a_coupon_past_its_expiry_date_is_refused_and_leaves_the_balance_alone(self) -> None:
        """Test that a coupon past its expiry is refused and leaves the balance alone."""

    # Good: the name identifies the case, the docstring states the behavior
    def test_an_expired_coupon(self) -> None:
        """Test that redeeming past the expiry is refused and leaves the balance alone."""
```

## Place Construction Outside Tests

Never define a builder in a test module, including for its first caller.

- Put structured model construction in the repository's configured factory type in the nearest
  repository-established shared factory location. With Polyfactory, that is a concrete
  `ModelFactory` or `SQLAlchemyFactory` in the nearest shared `factories.py`: set `__model__`,
  provide deterministic domain defaults, let it generate incidental valid values, express domain
  constraints and cross-field relationships without replacing its generation with a large manual
  `build()`, construct real nested relationships, and call `.build(**overrides)` directly from
  tests. Do not wrap a factory class in a pytest fixture solely for injection, and do not describe
  one with a `Protocol`.
- Put persisted flows, filesystem materialization, dependency lifecycles, and multi-object scenarios
  in a domain-named pytest factory fixture at the repository-established shared fixture location.
  Such a fixture returns a keyword-only inner builder named `_build` or for its specific action,
  never a bare `factory`. Filesystem and other I/O materialization takes typed factory-built models
  and explicit target paths.
- Keep a test module focused on composing fixtures, exercising behavior, and asserting outcomes.

Factories construct meaningful aggregates, complete boundary models, persisted roots, or
multi-object scenarios; a leaf value, a relationship row, or a payload fragment gets no factory and
is built through its owning root. A factory's name is domain-qualified — `create_order`,
`create_customer` — never generic, numbered, prefixed with setup mechanics such as `persisted_*`,
or suffixed with persistence mechanics such as `*_orm_factory`. Its inputs are typed aggregates or
boundary models rather than positional identity scalars, nested override dictionaries, relationship
rows, or payload fragments.

Prefer a ready, function-scoped fixture named for a domain role when each test needs one standard
instance, and prefer one that returns a real ORM instance for ORM-heavy tests. Add a callable
creation fixture only when tests genuinely need arbitrary independently configured instances.

```python
# Good: a domain-named persisted creation fixture in the suite's fixture package
@pytest.fixture
def create_order(order_fixture, customer_fixture, create_customer):
    """Build Order ORM instances with a nested real Customer relation."""

    def _build(**overrides):
        customer = create_customer()
        order = Orders(
            id=order_fixture.id,
            customer_id=customer_fixture.id,
            status=OrderStatus.PENDING,
        )
        order.customer = customer
        for key, value in overrides.items():
            setattr(order, key, value)
        return order

    return _build
```

A fixture is never defined in a test module either. A fixture beside the tests that use it is
invisible to every other module, so the next suite needing the same setup writes its own copy, and
one concept ends up with three implementations. Move it to the suite's fixture package, and where it
was autouse, keep its exact reach with a module-level `pytestmark = pytest.mark.usefixtures(...)`
rather than letting a shared definition widen it to the whole suite. The one fixture that may stay
nested is one defined inside a single test class, because nesting already scopes it to that class
and moving it would widen it.

A suite keeps its reusable fixtures in a `fixtures/` package of topic-named modules that its
`conftest.py` imports or registers, and keeps `conftest.py` for lifecycle wiring: the database
session, the event loop, autouse environment setup, plugin registration. A suite that puts domain
fixtures in `conftest.py` while its sibling puts them in `fixtures/` makes a reader look in two
places for the same thing. Name shared test modules for the domain or boundary they own rather than
introducing a `models.py`, `helpers.py`, or `utils.py` catch-all where a focused module is the
natural home.

When several tests need the same configuration overrides, expose one fixture helper in the suite's
fixture package instead of repeating `monkeypatch.setattr(...)` in each test:

```python
@pytest.fixture
def mock_config(monkeypatch):
    """Create a reusable config override helper for tests."""

    def _mock_config(**overrides) -> None:
        defaults = {
            "FEATURE_FLAG_ENABLED": False,
            "API_KEY": "test-api-key",
        }
        for key, value in {**defaults, **overrides}.items():
            monkeypatch.setattr(f"app.config.CONFIG.{key}", value)

    _mock_config()
    return _mock_config


async def test_extracts_tenant_from_token(mock_config):
    mock_config(
        ENVIRONMENT="development",
        ALLOWED_TEST_ENVIRONMENTS=("development", "staging"),
    )
```

For HTTP endpoint tests, build request payloads from the request models the application's routes
and services use, then serialize them through the suite's shared serialization helper, which owns
the repository's standard dump options; call `model_dump(...)` directly only where an endpoint
contract genuinely needs different options. Use enum members rather than hard-coded strings, derive
an invalid payload from a valid one and mutate it deliberately, and serialize mocked response bodies
from the application's response models rather than hand-rolled dictionaries. A test-only
`BaseModel` mirroring a contract is the fallback where no application model exists; a
`SimpleNamespace` never is.

```python
# Bad: a hard-coded property in a test payload
payload = {
    "website": "https://example.com",
}

# Good: add website to the shared fixture setup and use fixture data
assert account_fixture.website is not None
payload = {
    "website": account_fixture.website,
}
```

## Choose Test Doubles

Run the real code first. A repository-owned callable whose implementation is deterministic and stays
in the process — a predicate, a policy, a formatter, a normalization helper, a model method — runs
as itself, with its input arranged by the suite's fixtures. A repository-owned object — a request, a
settings object, a domain model, an ORM row, a result model, a scope or context object — is a real
instance from the suite's fixtures, its factories, or its own constructor. A flow that needs a row
proves itself at the tier that has the real database, and a lower tier keeps only the branch the
real path cannot reach; a conflict the database raises is produced by inserting the conflicting row,
never by patching `insert` to raise.

A double is for what the process cannot cross — a third-party SDK, the network, another service, the
filesystem, the clock, randomness, a subprocess — or for a fault the real path cannot produce. It
sits at the seam the application declares: the provider override, the fake, or the consuming
module's binding of the gateway. A patch one layer above that seam, a service wrapper instead of the
gateway binding it fronts, discards the logic the wrapper owns. Reach for doubles in this order, and
take the first that fits:

1. an injected fake or an override of the provider the application already exposes for the
   dependency, which is the seam the application declares;
2. a fake the third-party library ships or the repository maintains for it;
3. a reusable mock shape from the shared test-utilities package — an async context manager in
   place of a session factory, a connection, or a transaction is the same four lines wherever it
   appears, and each hand-rolled copy is a chance to get `__aexit__` subtly wrong, so it is built
   once, takes the yielded object as an argument, and is imported;
4. a patch, at the consuming module's own binding rather than the module that defines the symbol,
   and at the shallowest seam the consumer actually reads.

Use `AsyncMock` for async functions. `MagicMock` is acceptable for external boundaries such as SDK
response containers, subprocess handles, and network wrappers, and never for ORM or domain entities,
which come from concrete factories, ready fixtures, or domain-named creation fixtures returning real
instances. A mocked third-party library raises its real exception types, and a reusable fake prefers
real SDK or HTTP models and response objects over `MagicMock`.

Test the documented and implemented SDK contract, not speculative runtime shapes: no defensive test
for a surface the integration contract guarantees, and tests of a required SDK method focus on its
valid responses and real failure modes. Keep names and docstrings about behavior and outcomes rather
than SDK internals.

## Prove The Tests Detect The Regression

After all new or materially strengthened behavioral tests in the current implementation batch are
written, prove each distinct new guarantee with a temporary mutation of the repository-owned source
under test. A batch of one test still requires proof. Pure placement, naming, or prose changes that
claim no new behavior do not. Run the proof after the batch is written, not between test edits.

For each guarantee:

1. Select the nearest editable canonical first-party implementation. Never mutate vendored or
   generated output, and do not run generation for a temporary proof. Make the smallest change that
   violates the intended behavior without introducing an unrelated syntax, import, collection, or
   startup failure. Mutate the application or other owned implementation being tested, never the
   test itself. A test-support module is the target only when that module is genuinely the subject
   under test.
2. Before mutating, record the target's exact content and its version-control or workspace status,
   including staged and unstaged changes. Keep the mutation unstaged.
3. Use the narrowest repository-native test selection that contains the directly relevant new or
   updated cases. Require a failure whose assertion or observed outcome demonstrates the intended
   regression. A crash before the behavior is exercised is not proof. For parametrized coverage,
   confirm the newly added case detects its corresponding mutation.
4. Reverse only the temporary mutation and preserve every pre-existing or intended working-tree
   change. Never reset, check out, or otherwise discard unrelated work to restore the source.
5. Verify the target content and staged and unstaged state match the recorded baseline exactly, then
   rerun the affected tests successfully.

Never commit or push while a temporary mutation is present. Report the mutation, the expected
failure it produced, and the restored passing result. If no canonical repository-owned source can
be safely mutated without changing generated or vendored output, report the exact blocker and do
not claim the new behavioral test has been proven effective.

## Encountered Violations And Completion

Fix the concrete violations naturally found while reading the relevant tests, sibling service tests,
fixtures, factories, and shared utilities, at the breadth the product-constraints skill sets when
one is declared: misplaced tests, inconsistent sibling layouts, duplicate cases, long names, local
builders, and hard-coded fixture data. Fix and validate those pre-existing violations without
turning the task into an unrelated repository-wide audit.

After restoring every temporary mutation and completing all test and support changes, run the
locally available targets that cover the changed behavior. Use the full suite only when every tier is
relevant or the user requests it. Report the source-to-test placement, sibling conventions checked,
cases reused through parametrization, encountered corrections, mutation proofs, and final validation.
