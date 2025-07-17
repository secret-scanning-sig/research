# Generic Pattern Format

## Goal

Create a generic format that allows you to describe secret detection patterns
in a way that can easily translate into formats used by other tools. This is
make it easier to share patterns in a tool agnostic way.

## Last Updated

N/A - this project is newly created. We're still fleshing things out.

## [Draft] Methodology

(Edit this as we go to track how its done and then clean up before submitting
for review)

Rough outline (just a brain dump, this isn't set in stone):

- Look for existing tools that do this well (e.g. Sigma rules, [secret-patterns-db](https://github.com/mazen160/secrets-patterns-db), others?)
- Pick a set of initial translation targets (Splunk Search, Gitleaks, Trufflehog, Nosey Parker, GitHub Secret Scanning, some other really tricky one)
- Pick a set of initial patterns to try to write (pull from gitleaks, LeakTK, Nosey Parker, secret patterns db, others?).
- Collect the rules in this repo under something like `data/patterns/<provider>/<rule-file>` and include a README.md to cite where we pull the data from and add licenses if needed
- Start work on pulling out the common bits from those rules in a way way that easily translates[^1].
- Start scripting and testing the ability to use the detections effectively[^2].
- Define vocab as we go for the parts of a pattern in the SIG's glossary (might want to split this out of the main README as it grows).

[^1]: We'll want to make sure we split out the target from the context patterns
    because some tools have different regex scopes (e.g. Gitleak's allowlist
    has a regexTarget) or there may be cases where we do full matches against
    just a finding to verify it (e.g. if ML picks up a generic secret and we
    need to classify it).

[^2]: Not sure if we want to start building out a training/benchmarking repo at
    this point or test it another way. If we do want to start ping me
    (bplaxco), I have some ideas that might help us get started.

## [Draft] Results & Conclusion

(Pending Research)
