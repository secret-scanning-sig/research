import enum
import logging

from enum import StrEnum
from typing import Annotated
from typing import Any
from typing import Literal

import tomlkit

from pydantic import BaseModel
from pydantic import Field

from sssig_rules.schema import OptionalPositiveFloat
from sssig_rules.schema import OptionalPositiveInt
from sssig_rules.schema import Pattern
from sssig_rules.schema import Rule
from sssig_rules.schema import FilterKind
from sssig_rules.schema import Filter

from .common import _or_patterns
from .common import _match_pattern
from .common import _strings_to_pattern

logger = logging.getLogger(__name__)


class _RegexTarget(StrEnum):
    LINE = enum.auto()
    MATCH = enum.auto()
    SECRET = enum.auto()


class _AllowlistCondition(StrEnum):
    AND = enum.auto()
    OR = enum.auto()


class _Allowlist(BaseModel):
    condition: _AllowlistCondition
    regex_target: Annotated[
        _RegexTarget | None, Field(serialization_alias="regexTarget")
    ] = None
    paths: list[Pattern] | None = None
    regexes: list[Pattern] | None = None
    stopwords: list[str] | None = None


class _Required(BaseModel):
    id: str
    within_lines: Annotated[
        int | None, Field(ge=0, serialization_alias="withinLines")
    ] = None
    within_columns: Annotated[
        int | None, Field(ge=0, serialization_alias="withinColumns")
    ] = None


class _Rule(BaseModel):
    id: str
    description: str | None = None
    path: Pattern | None = None
    regex: Pattern | None = None
    entropy: OptionalPositiveFloat = None
    keywords: list[str] | None = None
    tags: list[str] | None = None
    skip_report: Annotated[bool, Field(serialization_alias="skipReport")]
    allowlists: list[_Allowlist] | None = None
    required: list[_Required] | None = None


class _Config(BaseModel):
    rules: list[_Rule]


def _required_filters(rule: Rule) -> list[Filter]:
    return [f for f in (rule.filters or []) if f.kind == FilterKind.REQUIRE]


def _keywords(rule: Rule) -> list[str] | None:
    if not rule.filters:
        return None

    keywords = []
    for f in rule.filters:
        if f.kind != FilterKind.REQUIRE:
            continue

        if f.context_strings:
            keywords.extend(f.context_strings)

        if f.target_strings:
            keywords.extend(f.target_strings)

    return keywords or None


def _entropy(rule: Rule) -> float | None:
    req_filters = _required_filters(rule)
    if not req_filters:
        return None

    entropy = 0
    for f in req_filters:
        if f.target_min_entropy and f.target_min_entropy > entropy:
            entropy = f.target_min_entropy

    return entropy or None


def _regex(rule: Rule) -> Pattern:
    return _match_pattern(rule)


def _path_patterns(f: Filter) -> list[Pattern] | None:
    patterns = []

    if f.path_patterns:
        patterns.extend(f.path_patterns)

    if f.path_strings:
        patterns.extend(_strings_to_pattern(f.path_strings))

    return patterns or None


def _path(rule: Rule) -> Pattern | None:
    return _or_patterns(list(map(_path_patterns, _required_filters(rule))))


def _tags(rule: Rule) -> list[str]:
    tags = [
        f"kind:{rule.meta.kind}",
    ]

    if rule.meta.confidence:
        tags.append(f"confidence:{rule.meta.confidence}")

    if rule.meta.tags:
        tags.extend(rule.meta.tags)

    return tags


def _required(rule: Rule) -> list[_Required] | None:
    if not rule.dependencies:
        return None

    return [
        _Required(
            id=d.rule_id,
            within_lines=d.within_lines,
            within_columns=d.within_columns,
        )
        for d in rule.dependencies
    ]


def _id(rule: Rule) -> str:
    return rule.id


def _description(rule: Rule) -> str | None:
    return rule.meta.description or rule.meta.name


def _skip_report(rule: Rule) -> bool:
    return not rule.meta.report


def _allowlist_regexes(
    rule: Rule, f: Filter
) -> tuple[_RegexTarget | None, list[Pattern] | None]:
    # Gitleaks can't handle multiple allowlist pattern scopes AND'd together
    # so this tries to do the best it can to set the target correctly when
    # there are multiple scopes in the same rule
    patterns: list[Pattern] = []
    regex_target: _RegexTarget | None = None

    if f.context_patterns or f.context_strings:
        regex_target = _RegexTarget.LINE

        if f.context_patterns:
            patterns.extend(f.context_patterns)

        if f.context_strings:
            patterns.append(_strings_to_pattern(f.context_strings))

    if f.match_patterns or f.match_strings:
        if regex_target:
            logger.warning(
                "applying match patterns with a '%s' regex target", regex_target
            )
        else:
            regex_target = _RegexTarget.MATCH

        if f.match_patterns:
            patterns.extend(f.match_patterns)

        if f.match_strings:
            patterns.append(_strings_to_pattern(f.match_strings))

    if f.target_patterns:
        if regex_target:
            logger.warning(
                "applying target patterns with a '%s' regex target", regex_target
            )
        else:
            regex_target = _RegexTarget.SECRET

        if f.target_patterns:
            patterns.extend(f.target_patterns)

    if not patterns:
        return None, None

    return regex_target, patterns


def _allowlists(rule: Rule) -> list[_Allowlist] | None:
    exc_filters = [f for f in (rule.filters or []) if f.kind == FilterKind.EXCLUDE]

    if not exc_filters:
        return None

    allowlists = []
    for f in exc_filters:
        regex_target, patterns = _allowlist_regexes(rule, f)
        allowlists.append(
            _Allowlist(
                condition=_AllowlistCondition.AND,
                stopwords=f.target_strings,
                paths=_path_patterns(f),
                regexes=patterns,
                regex_target=regex_target,
            )
        )

    return allowlists or None


def _rule(rule: Rule) -> _Rule:
    if rule.analyzers is not None:
        logger.warning(
            "rule.analyzers ignored in gitleaks: rule_id=%r",
            rule.id,
        )

    return _Rule(
        id=_id(rule),
        description=_description(rule),
        path=_path(rule),
        regex=_regex(rule),
        entropy=_entropy(rule),
        keywords=_keywords(rule),
        tags=_tags(rule),
        required=_required(rule),
        allowlists=_allowlists(rule),
        skip_report=_skip_report(rule),
    )


def _config(rules: [Rule]) -> _Config:
    return _Config(rules=list(map(_rule, rules)))


def translate(rules: list[Rule]) -> str:
    return tomlkit.dumps(_config(rules).model_dump(exclude_none=True))
