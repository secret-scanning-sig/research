import enum

from enum import StrEnum

from sssig_rules.targets import gitleaks
from sssig_rules.targets import splunk
from sssig_rules.targets import noseyparker
from sssig_rules.targets import kingfisher


__all__ = [
    "gitleaks",
    "splunk",
    "noseyparker",
    "kingfisher",
]


class TargetKind(StrEnum):
    GITLEAKS = enum.auto()
    SPLUNK = enum.auto()
    NOSEYPARKER = enum.auto()
    KINGFISHER = enum.auto()
