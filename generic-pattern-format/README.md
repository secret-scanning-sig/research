# Generic Pattern Format

## Goal

The goal of was to create a generic, tool-agnostic format for describing secret
detection patterns. This allows for the easy translation of patterns into
various formats used by different security tools, simplifying the sharing and
maintenance of detection logic. It is not intended to replace native tool
formats but to be compiled into them.

## Last Updated

2025-09-07

## Methodology

Inspiration was initially drawn from the [Sigma project](https://sigmahq.io/)
for SIEMs. So the core of the solution is a structured, YAML-based format that
can capture detection logic, including multi-part secrets, contextual keywords,
and validation steps.

## Implementation

### Translation Targets

Based on an analysis of the current secret scanning ecosystem, the following
tools were selected as example translation targets:

* GitHub Secret Protection
* Gitleaks
* Nosey Parker
* Kingfisher
* TruffleHog

### Schema Definition

The pattern schema is defined using Python Pydantic models to ensure it is
well-defined, easy to parse, and simple to validate.

The schema can be viewed here: [src/sssig\_rules/schema.py](src/sssig_rules/schema.py)

### Example Usage

The reference implementation includes a script to demonstrate the translation
process.

1.  **Build Hyperscan dependency:**
    ```sh
    cd src
    make
    ```

2.  **Run the translation script:**
    ```sh
    ./main.py -t {gitleaks|noseyparker|etc} ../data/rules/sssig.yaml
    ```

### Example Translations

The other files in [data/rules](data/rules) were compiled via:

```sh
cd src && make
./main.py -t noseyparker ../data/rules/sssig.yaml > ../data/rules/noseyparker.yaml
./main.py -t gitleaks    ../data/rules/sssig.yaml > ../data/rules/gitleaks.toml
./main.py -t kingfisher  ../data/rules/sssig.yaml > ../data/rules/kingfisher.yaml
./main.py -t github      ../data/rules/sssig.yaml > ../data/rules/github.json
./main.py -t trufflehog  ../data/rules/sssig.yaml > ../data/rules/trufflehog.yaml
```

## Results & Conclusion

The final format defined in `src/sssig_rules/schema.py` provides a starting
point for a common secret detection rule format. Future development can take
place in the rules repo as we add more targets and improve the format.

### Key Features of the Format

* **Structured & Typed:** The format is declarative and typed, making it easy
  to parse, validate, and translate.
* **Expressive Detection Logic:** It can represent not just regexes, but also:
  * Multi-part secrets (e.g., `client_id` and `client_secret`).
  * Contextual keywords and surrounding patterns.
  * Entropy checks.
  * Active validation steps.
* **Metadata:** Includes fields for rule ID, name, description, severity,
  confidence, and references, providing context for analysts.
