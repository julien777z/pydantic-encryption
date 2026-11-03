from typing import Final

SEALED_CONTEXT: Final[bytes] = b"tests.records.secret"
FOREIGN_CONTEXT: Final[bytes] = b"tests.records.other_secret"
CALLER_CONTEXT: Final[bytes] = b"tests.caller"

PLAINTEXTS: Final[list[str]] = [
    "",
    "secret data",
    "日本語 한국어 العربية 🎉🔒",
    '!@#$%^&*()_+-={}[]|\\:";<>?,./~`',
]
PLAINTEXT_IDS: Final[list[str]] = ["empty", "ascii", "unicode", "punctuation"]
