"""
This submodule handles conversion of entries (which are both Collections, which
are basically directories, and Documents, which are files) to and from the JSON
format used by the reMarkable API.

JSON payloads are cast to Pydantic models for validation and serialization.
"""

from typing import List, Literal, Union
import warnings
import pydantic


class CollectionEntry(pydantic.BaseModel):
    id: str
    hash: str
    type: str
    visibleName: str
    lastModified: str
    pinned: bool
    parent: str | None = None


class DocumentEntry(pydantic.BaseModel):
    id: str
    hash: str
    type: str
    visibleName: str
    lastModified: str
    fileType: str
    parent: str | None = None
    pinned: bool
    lastOpened: str


Entry = Union[CollectionEntry, DocumentEntry]

EntryLookup = {
    "CollectionType": CollectionEntry,
    "DocumentType": DocumentEntry,
}


def parse_entries(
    data: list[dict[str, str]],
    fail_method: Literal["raise", "warn", "ignore"] = "raise",
) -> List[Entry]:
    """
    Parse a JSON string into a list of Entry objects.

    Arguments:
        data: A JSON string representing the entries.
        fail_method: The method to use when parsing fails. Can be "raise" (in
            which case an exception will be raised) or "ignore" (in which case
            that entry will be skipped). Or "warn" (in which case a warning
            will be logged).

    Returns:
        A list of Entry objects.
    """
    entries = []
    for entry_data in data:
        entry_type = entry_data.get("type")
        entry_model = EntryLookup.get(entry_type)
        if entry_model is None:
            if fail_method == "raise":
                raise ValueError(f"Unknown entry type: {entry_type}")
            elif fail_method == "warn":
                warnings.warn(f"Unknown entry type: {entry_type}. Skipping.")
                continue
            elif fail_method == "ignore":
                continue
        else:
            try:
                entries.append(entry_model(**entry_data))
            except pydantic.ValidationError as e:
                if fail_method == "raise":
                    raise e
                elif fail_method == "warn":
                    warnings.warn(f"Validation error for entry {entry_data}: {e}")
                elif fail_method == "ignore":
                    continue
    return entries


__all__ = ["CollectionEntry", "DocumentEntry", "Entry", "parse_entries"]
