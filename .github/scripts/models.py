from typing import TypedDict


class PublicSymbol(TypedDict):
    """One symbol pyright's type completeness report inspects."""

    name: str
    isExported: bool
    isTypeKnown: bool
    isTypeAmbiguous: bool


class TypeCompleteness(TypedDict):
    """The type completeness section of pyright's verifytypes report."""

    completenessScore: float
    symbols: list[PublicSymbol]


class VerifyTypesReport(TypedDict):
    """Pyright's JSON verifytypes report."""

    typeCompleteness: TypeCompleteness
