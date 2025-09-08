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

- GitHub Secret Protection
- Gitleaks
- Nosey Parker
- TruffleHog

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
make it easier to translate. I chose YAML since it handles block text easier
and escaping complicated strings isn't too difficult.

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

The converted format can be found at `data/rules/sssig.toml`

The schema is at `src/sssig_rules/schema.py`

The script can be run vi:

```sh
cd src
make # needed to build the hyperscan dep
./main.py -t {type} ../data/rules/sssig.toml
```

## Results & Conclusion

The final format defined in `src/sssig_rules/schema.py` looks like a promising
start for the rule format. Further tweaks and developments can happen in
our common rules project. This can be kept around to show the process and how
the initial format was reached.

Also if we decide that the toml format is unweildly any data format that can be
loaded into a python dict and serialized into json/yaml/toml/etc should do.
