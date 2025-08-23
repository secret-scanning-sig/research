# Generic Pattern Format

## Goal

Create a generic format that allows you to describe secret detection patterns
in a way that can easily translate into formats used by other tools. This is
make it easier to share patterns in a tool agnostic way.

## Last Updated

N/A - this project is newly created. We're still fleshing things out.

## Methodology

### Translation Target Selection

I took a draft of this doc with a rough outline. I provided it to Gemini 2.5
pro using the deep research feature to help with finding existing tools and
translation targets that I may have not considered:

- [Prompt](data/gemini-deep-research/initial-research-prompt.md)
- [Results](data/gemini-deep-research/initial-research-results.md)

Based on the above, I've selected the following tools for my translation
targets:

- Bash + GNU Coreutils + Grep
- GitHub Secret Protection
- Gitleaks
- Nosey Parker
- Splunk
- Sumo Logic
- TruffleHog
- YARA

### Regex Format Selection

I decided to use a regular expression format consisting of a common subset of
PCRE's features found in these libraries since that should result in very
portable patterns:

- github.com/golang/go/tree/master/src/regexp
- github.com/intel/hyperscan
- github.com/python/cpython/tree/main/Lib/re
- github.com/rust-lang/regex

[Hyperscan's pattern support docs](https://intel.github.io/hyperscan/dev-reference/compilation.html#pattern-support)
acted as a list of features to look for in the other libraries since it seemed
to be the most restrictive of the PCRE implementations.

Current recommendations on character escapes:

- Escape single quotes, double quotes, and backticks.
- Escape all metacharacters not being used as metacharacters, even when a
  regex engine wouldn't interpret them as a metacharacter.

It makes it easier to copy/paste them into a SIEM or a terminal without needing
to make small changes to the patterns which could cause issues and makes them
more difficult to use. The translator should handle these cases, but being able
to easily do it by hand without changing them makes them easier to maintain and
use for hunting.

### Pattern Format Selection

After selecting the targets and process for picking a regex formats, I began
looking at existing wide spread detection formats like Sigma and YARA
for inspiration for the format.

I decided to start with a format that is specific, typed, and declarative to
make it easier to translate. I also chose TOML since it is compact, simple, and
makes escaping more complicated strings easier with triple single quotes.

Also for IDs I used:

```sh
echo "S3IG$(openssl rand 10 | basenc --base32)"
```

I defined the schema using models to make it easier to parse, test and
validate.

You can view it here: [src/sssig\_rules/schema.py](src/sssig_rules/schema.py)

### Initial Rule Selection

I selected a few rules for Gitleaks, Nosey Parker, and YARA that:

- Leverage most of the tool's features or have complex logic
- Are large and potentially unwieldy to write

They can be found under `data/rules/{gitleaks.toml,noseyparker.yaml,yara.yar}`.

### Scratchpad

Below this point is just my scratchpad that will be converted into workbook
notes above.

Rough remaining item list:

- Start work on pulling out the common bits from those rules in a way way that easily translates[^1].
- Start scripting and testing the ability to use the detections effectively[^2].
- How to provide better detections for things that can support it vs basic detections for things that might only offer basic options[^3].
- Define vocab as we go for the parts of a pattern in the SIG's glossary (might want to split this out of the main README as it grows).

[^1]: We'll want to make sure we split out the target from the context patterns
    because some tools have different regex scopes (e.g. Gitleak's allowlist
    has a regexTarget) or there may be cases where we do full matches against
    just a finding to verify it (e.g. if ML picks up a generic secret and we
    need to classify it).

[^2]: Not sure if we want to start building out a training/benchmarking repo at
    this point or test it another way. If we do want to start ping me
    (bplaxco), I have some ideas that might help us get started.

[^3]: Some things to think about: just pattern target, extra indicators (both positive and negative), conditions (and how to translate those), etc

## [Draft] Results & Conclusion

(Pending Research)
