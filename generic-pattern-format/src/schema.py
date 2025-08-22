from enum import StrEnum
from enum import auto
from pathlib import Path
from re import Pattern
from typing import Annotated
from typing import Union

from pydantic import BaseModel
from pydantic import HttpUrl
from pydantic import Field


RuleId = Annotated[str, Field(pattern="^SSSIG[A-Z2-7]{16}$")]
OptionalPositiveInt = Annotated[int | None, Field(ge=0)]
OptionalPositiveFloat = Annotated[float | None, Field(ge=0)]
VariableName = Annotated[str, Field(pattern="^[a-z](?:[a-z0-9_]*[a-z0-9])?$")]


class Confidence(StrEnum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()


class Syntax(StrEnum):
    HTML = auto()
    JSON = auto()
    XML = auto()


class TargetKind(StrEnum):
    # The default kind if unset
    UNKNOWN = auto()

    # Not an exhaustive list, just an example
    AWS_ACCESS_KEY_ID = auto()
    AWS_SECRET_ACCESS_KEY = auto()
    HOSTNAME = auto()
    URL = auto()
    ANTHROPIC_API_KEY = auto()
    DOCKER_SWARM_JOIN_TOKEN = auto()
    GITHUB_APP_INSTALLATION_ACCESS_TOKEN = auto()
    GOOGLE_API_KEY = auto()
    TERRAFORM_API_TOKEN = auto()
    HEROKU_PLATFORM_API_OAUTH3_TOKEN = auto()
    HF_USER_ACCESS_TOKEN = auto()
    NOTION_API_TOKEN = auto()
    NPM_ACCESS_TOKEN = auto()
    OPENAI_API_KEY = auto()
    PERPLEXITY_API_KEY = auto()


class Examples(BaseModel):
    positive: list[str] | None = None
    negative: list[str] | None = None


class Meta(BaseModel):
    # Rate the quality of the item
    confidence: Confidence | None = None
    # Provide pos/neg examples for this item
    examples: Examples | None = None
    # Provide references for how it was created
    references: list[HttpUrl] | None = None
    # Set whether or not the result of this should be included in the report
    report: bool = True
    # Tags for additional context and categorization
    tags: list[str] | None = None


class Target(BaseModel):
    kind: TargetKind = TargetKind.UNKNOWN
    name: str
    description: str
    pattern: Pattern


class FilterMode(StrEnum):
    REQUIRE = auto()
    EXCLUDE = auto()


class TargetMatcher(BaseModel):
    max_entropy: OptionalPositiveFloat = None
    min_entropy: OptionalPositiveFloat = None
    prefix: Pattern | None = None
    suffix: Pattern | None = None
    strings: list[str] | None = None


class ContextMatcher(BaseModel):
    patterns: list[Pattern] | None = None
    strings: list[str] | None = None


class PathMatcher(BaseModel):
    paths: list[Pattern] | None = None


class HttpMatcher(BaseModel):
    statuses: list[int] | None = None
    headers: dict[str, list[str]] | None = None

    body_strings: list[str] | None = None
    body_patterns: list[Pattern] | None = None
    body_syntax: Syntax | None = None


class Filter(BaseModel):
    mode: FilterMode

    # These are AND'd, for OR, define multiple filters
    condition: list[
        Union[
            ContextMatcher,
            TargetMatcher,
            PathMatcher,
        ]
    ]


class AnalyzerKind(StrEnum):
    HTTP = auto()


class AnalyzerHttpAction(BaseModel):
    url: HttpUrl
    method: str | None = None
    headers: dict[str, str] | None = None
    body: str | None = None
    timeout: OptionalPositiveFloat = None


class Analyzer(BaseModel):
    kind: AnalyzerKind
    meta: Meta
    action: Union[AnalyzerHttpAction,]

    # these are AND'd
    condition: list[Union[HttpMatcher,]]


class Dependancy(BaseModel):
    rule_id: RuleId
    varname: VariableName
    within_lines: OptionalPositiveInt = None
    within_columns: OptionalPositiveInt = None


class Rule(BaseModel):
    id: RuleId
    meta: Meta
    dependencies: list[Dependancy] | None = None
    target: Target
    filters: list[Filter] | None = None
    analyzers: list[Analyzer] | None = None
