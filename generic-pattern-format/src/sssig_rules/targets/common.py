import logging
import re

from sssig_rules.schema import Pattern
from sssig_rules.schema import Rule

logger = logging.getLogger(__name__)


def _match_pattern(rule: Rule) -> Pattern:
    prefix = _pattern_str(rule.target.prefix_pattern, noncapture_group=True)
    suffix = _pattern_str(rule.target.suffix_pattern, noncapture_group=True)
    target = _pattern_str(rule.target.pattern, capture_group=bool(prefix or suffix))
    return Pattern(f"{prefix}{target}{suffix}")


def _pattern_str(
    pattern: Pattern | None,
    capture_group: bool = False,
    noncapture_group: bool = False,
) -> str:
    assert not (
        capture_group and noncapture_group
    ), "patterns can't be both capture groups and non-capture groups"

    if pattern is None:
        return ""
    elif capture_group:
        return f"({pattern})"
    elif noncapture_group:
        return f"(?:{pattern})"
    else:
        return str(pattern)


def _strings_to_pattern(strings: list[str]) -> Pattern | None:
    match len(strings):
        case 0:
            return None
        case 1:
            return Pattern(f"(?i){re.escape(strings[0]).lower()}")
        case _:
            return Pattern(
                "(?i)" + "|".join(f"(?:{re.escape(s).lower()})" for s in strings)
            )


def _or_patterns(patterns: list[Pattern]) -> Pattern | None:
    match len(patterns):
        case 0:
            return None
        case 1:
            return patterns[0]
        case _:
            return Pattern("|".join(f"(?:{p})" for p in patterns))
