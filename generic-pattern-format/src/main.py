#!/usr/bin/env python3
import sys
import tomllib

from argparse import ArgumentParser
from argparse import Namespace
from enum import StrEnum
from enum import auto
from pathlib import Path

from schema import Rule


class Format(StrEnum):
    GITLEAKS = auto()
    SPLUNK = auto()
    NOSEYPARKER = auto()
    KINGFISHER = auto()


def main(args: list[str]) -> int:
    try:
        _translate(_parse_args(args))
    except Exception as e:
        print("ERROR:", e, file=sys.stderr)
        return 1

    return 0


def _translate(opts):
    fmt = opts.format
    rules = _load_rules(opts.rulespath)
    return globals()["_translate_{fmt}"](rules)


def _load_rules(rulespath: Path) -> list[Rule]:
    with rulespath.open(encoding="utf-8") as rulesfile:
        return [
            Rule.parse_obj(rule_data) for rule_data in tomlib.load(rulesfile)["rules"]
        ]


def _parse_args(args: list[str]) -> Namespace:
    parser = ArgumentParser(
        prog="translate",
        description="translate rules",
    )
    parser.add_argument(
        "rulespath",
        type=Path,
    )
    parser.add_argument(
        "--format",
        type=Format,
        choices=list(Format),
        required=True,
    )
    opts = parser.parse_args(args)
    if not opts.rulespath.is_file():
        raise ValueError(f"provided rulespath does not exist")
    return opts


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
