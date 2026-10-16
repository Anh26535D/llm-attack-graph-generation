"""Compatibility imports for the shared, description-grounded E1 conditions."""

from crystalball.validation.conditions import (
    CONDITIONS, LEVELS, CveCondition, VersionRange, parse_version,
)

__all__ = ["CONDITIONS", "LEVELS", "CveCondition", "VersionRange", "parse_version"]
