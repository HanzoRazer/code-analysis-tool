"""Positive fixture: if/elif chain without else clause."""
from enum import StrEnum


class OutputFormat(StrEnum):
    CSV = "csv"
    JSON = "json"
    XML = "xml"


def serialize_data(data: dict, fmt: OutputFormat) -> str:
    if fmt == OutputFormat.CSV:
        return ",".join(data.keys())
    elif fmt == OutputFormat.JSON:
        return str(data)
    # Missing XML handler, no else clause
    # SHOULD FIRE: SF_INCOMPLETE_DISPATCH_001
