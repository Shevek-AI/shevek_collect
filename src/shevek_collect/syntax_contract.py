from __future__ import annotations

from typing import Any

SYNTAX_OBSERVATIONS_SCHEMA_VERSION = "shevek.syntax_observations.v2"

REFERENCE_KINDS = frozenset({"read", "write", "execute", "defined_on", "reference"})
REFERENCE_TARGET_FORMS = frozenset({"identifier", "temporary", "dynamic"})


def empty_syntax(**extra: Any) -> dict[str, object]:
    """Return the stable, language-neutral syntax observation envelope.

    The contract deliberately separates non-call symbolic references from imports and
    call sites. Producers may leave fields empty when the language cannot express or
    conservatively recover that observation type.
    """

    return {
        "schema_version": SYNTAX_OBSERVATIONS_SCHEMA_VERSION,
        "symbols": [],
        "imports": [],
        "call_sites": [],
        "references": [],
        "scopes": [],
        "exports": [],
        "publics": [],
        "includes": [],
        "styles": [],
        "style_imports": [],
        **extra,
    }
