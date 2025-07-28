# Generic Pattern Format

## Goal

Create a generic format that allows you to describe secret detection patterns
in a way that can easily translate into formats used by other tools. This is
make it easier to share patterns in a tool agnostic way.

## Last Updated

N/A - this project is newly created. We're still fleshing things out.

## Methodology

I took a draft of this doc with a rough outline. I provided it to Gemini 2.5
pro using the deep research feture to help with finding existing tools and
translation targets that I may have not considered:

- [Prompt](data/gemini-deep-research/initial-research-prompt.txt)
- [Results](data/gemini-deep-research/initial-research-results.txt)

Based on the above, I've selected the following tools for my translation
targets:

- Bash + GNU Coreutils + Grep
- GitHub Secret Protection
- GitLeaks
- Nosey Parker
- Splunk
- Sumo Logic
- TruffleHog
- YARA

### Scratchpad

Below this point is just my scratchpad that will be converted into workbook
notes above.

Rough remaining item list:

- Look for existing tools that do this well for ideas (e.g. Sigma rules, [secret-patterns-db](https://github.com/mazen160/secrets-patterns-db), others?) and check if there's already an [existing standard](https://xkcd.com/927/) for this.
- Pick a set of initial patterns to try to write (pull from gitleaks, LeakTK, Nosey Parker, secret patterns db, others?).
- Collect the rules in this repo under something like `data/patterns/<provider>/<rule-file>` and include a README.md to cite where we pull the data from and add licenses if needed
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

[^3]: Some things to think about: just pattern target, extra indicators (both postive and negative), conditions (and how to translate those), etc

## [Draft] Results & Conclusion

(Pending Research)
