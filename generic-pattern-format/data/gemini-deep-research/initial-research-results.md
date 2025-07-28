# **A Universal Grammar for Secrets: A Framework for a Tool-Agnostic Detection Pattern Format**

## **Section 1: The Case for a Standardized Secret Detection Format**

The landscape of secret detection is characterized by a vibrant but fragmented ecosystem of powerful tools. While this diversity has spurred innovation, it has also erected significant barriers to collaboration and operational efficiency. Security teams often employ multiple scanners, each with its own proprietary rule format and detection philosophy, leading to duplicated effort, inconsistent coverage, and an inability to share threat intelligence effectively. This report outlines a framework for a universal, tool-agnostic secret detection pattern format. The objective is not to create another competing standard but to establish a *lingua franca*—a common, expressive language that can be translated to the native formats of existing tools. By learning from successful precedents in other security domains and analyzing the capabilities of modern scanners, a standardized grammar for describing secrets can be developed, fostering a more collaborative and effective community defense.

### **1.1 The "Tower of Babel" Problem in Secret Scanning**

The current state of secret detection resembles a digital Tower of Babel. Each scanning tool, whether open-source or commercial, speaks its own language.1 A rule meticulously crafted for Gitleaks is unintelligible to TruffleHog; a pattern defined in Nosey Parker cannot be used by GitHub's native scanning engine. This fragmentation creates significant operational friction. Organizations that leverage a multi-tool strategy—a common practice for defense-in-depth—are forced to maintain parallel, and often divergent, sets of detection rules. The manual effort required to translate, test, and synchronize these rule sets is substantial and error-prone.4

This lack of interoperability stifles community-driven security. When a researcher discovers a new, high-risk secret format, there is no common medium to share that detection logic. A new Gitleaks rule must be independently re-implemented for every other tool, delaying the community's ability to respond to emerging threats. This vendor lock-in, even among open-source projects, prevents the pooling of collective knowledge and creates silos of detection capability.5 The result is a systemic inefficiency that benefits adversaries, who can exploit the same leaked secret patterns across different environments while defenders struggle to share the antidote.

### **1.2 Learning from Prior Art: The Sigma Project as a Blueprint**

To solve this problem, one need not start from a blank slate. The domain of Security Information and Event Management (SIEM) faced a similar challenge, which was effectively addressed by the Sigma project.7 Sigma introduced a generic, open signature format for describing log events that is both human-readable (YAML) and highly structured.9 Its core innovation is not just the format itself, but the ecosystem built around it, most notably the

sigmac compiler, which translates a single Sigma rule into native query languages for dozens of different SIEMs and security platforms, including Splunk, Elasticsearch, and QRadar.8

The architectural elegance of Sigma lies in its clear, modular structure, which separates a rule into three primary components:

1. **Metadata:** Contains descriptive information such as the rule's ID, title, author, severity, and references.7
2. **Logsource:** Specifies the type of log data the rule applies to, defining the context of the search.7
3. **Detection:** Defines the actual search logic, using named selections and a final condition expression to combine them.7

This separation of concerns is the key to Sigma's translatability. The detection logic is abstract, allowing the sigmac compiler to map it to the specific syntax and capabilities of each target platform. This model provides a powerful blueprint for a universal secret detection format, demonstrating that a well-designed intermediate representation can successfully bridge the gap between disparate systems.

### **1.3 Evaluating Existing Pattern Collections**

The community has already made significant strides in aggregating secret patterns. The secrets-patterns-db project, for instance, stands as the largest open-source collection of regular expressions for detecting secrets, with over 1600 patterns.10 This repository is an invaluable resource, providing a vast library of tested regexes that can feed various scanning engines.

However, its primary limitation is that it is a *collection of patterns*, not a *format for describing detection logic*. It is a dictionary, not a grammar. Advanced secret scanners employ logic far richer than a single regular expression. They utilize contextual keywords, entropy analysis, multi-part pattern matching, and active validation to achieve high fidelity.11 The

secrets-patterns-db format, being a simple list of regexes, cannot encapsulate this sophisticated logic.10 For example, it cannot express a rule that requires both a

client\_id and a client\_secret to be present in close proximity, nor can it specify a validation endpoint to verify a found key.

The goal of this SIG, therefore, is not to replicate the work of secrets-patterns-db but to build upon it. The proposed universal format must be capable of representing not only the raw regex patterns found in such databases but also the complex, multi-faceted detection logic employed by state-of-the-art scanning engines. The challenge lies in defining a schema that can represent these advanced concepts, treating the regex as just one component of a larger, structured detection object.

### **1.4 The XKCD "Standards" Problem and How to Avoid It**

A valid and frequently raised concern in any standards effort is the risk of simply creating "one more competing standard," as humorously depicted in the popular webcomic XKCD. This initiative is acutely aware of that pitfall. The proposed solution is not to replace the native rule formats of Gitleaks, TruffleHog, or any other tool. These native formats are often highly optimized for their specific engine and use case.

Instead, the goal is to create a universal *interchange format*—a pivot language that enables interoperability. The primary deliverable and the source of its value is not just the format specification, but the translation engine that accompanies it. This "secret-sigma-compiler" would consume a rule written in the generic format and output an equivalent, optimized rule for a specific target tool. This approach respects the existing ecosystem by allowing tools to continue using their native formats while empowering the community to write, share, and consume detection logic in a single, common language. The success of this endeavor is therefore directly proportional to the quality and utility of its translation engine; the format and the translator are two halves of a single solution.

## **Section 2: A Comparative Analysis of Modern Secret Detection Engines**

To design a universal format that is both expressive and translatable, it is essential to first deconstruct the capabilities of existing secret detection tools. This section provides a detailed comparative analysis of the rule formats and detection logic for a representative set of scanners, from simple command-line utilities to sophisticated, enterprise-grade systems. The features and limitations identified here will form the basis for the proposed generic schema in the subsequent section.

### **2.1 Gitleaks: Simplicity and Extensibility**

Gitleaks is a widely used open-source scanner known for its speed and ease of use. Its rules are defined in a TOML configuration file, typically .gitleaks.toml, which provides a straightforward structure for defining detection patterns.13

* **Format and Core Components:**
  * **regex:** This is the primary field, containing a regular expression that defines the pattern of the secret itself.14
  * **keywords:** An optional list of strings that serve as a high-performance pre-filter. A line or commit diff must contain at least one of these keywords for the more expensive regex to be applied, significantly improving accuracy and speed.14
  * **description, id, tags:** These metadata fields are crucial for identifying, managing, and categorizing rules, allowing for better organization and reporting.14
  * **Entropies:** Gitleaks supports an optional block for calculating the Shannon entropy of specific regex capture groups. This is particularly useful for generic rules that aim to find high-randomness strings without a fixed pattern.16
  * **allowlist:** The format provides a mechanism to define global or rule-specific exclusions based on regular expressions, file paths, or specific commit hashes, which is essential for managing false positives in a real-world environment.13
* Noteworthy Features and Limitations:
  The Gitleaks format has proven to be extensible. GitLab, for example, enhances the standard format within its platform by adding title and remediation fields, providing users with richer context and actionable guidance when a secret is found.14 This demonstrates a clear demand for more comprehensive metadata than the base tool offers.
  However, the format has limitations. It lacks a native structure for defining multi-part secrets (e.g., a username and password that must appear together). While this can sometimes be approximated with complex, multi-line regular expressions, the format itself does not provide a clear or robust mechanism for expressing such relationships.17 Furthermore, Gitleaks has no built-in capability for active validation of found secrets.

### **2.2 TruffleHog: High-Fidelity through Multi-Pattern Logic and Validation**

TruffleHog is another prominent open-source scanner that prioritizes high-fidelity detections by incorporating advanced logic and active validation into its rule format. Its detectors are configured in a config.yaml file.19

* **Format and Core Components:**
  * **name:** A unique string that identifies the custom detector.19
  * **keywords:** Similar to Gitleaks, this is an array of strings used to trigger a more detailed regex search.19
  * **regex:** This is a key differentiator. Instead of a single regex, this field is a map of one or more *named* regular expressions. For a finding to be reported, *every* named regex in the map must find a match within the scanned content. This provides a clean and powerful mechanism for detecting multi-part secrets, such as an OAuth client\_id and client\_secret pair.19
  * **verify:** This optional block is TruffleHog's most advanced feature. It allows the rule to specify a webhook endpoint. When a potential secret is found, TruffleHog sends the captured values to this endpoint. A 200 OK response from the verification server confirms the secret is active, effectively eliminating false positives and allowing security teams to prioritize live credentials.19
  * **Advanced Parameters:** The format also supports additional parameters for fine-tuning, including entropy checks, exclude\_words, exclude\_regexes\_match, and primary\_regex\_name (which specifies which part of a multi-part match should be used to determine the finding's line number).19
* Noteworthy Features and Limitations:
  The active verification mechanism is a paradigm shift from passive pattern matching to active confirmation, representing the current state-of-the-art in high-fidelity secret detection. The tool's documentation explicitly notes its use of the Golang regex engine and the importance of using global multiline flags for certain patterns, which is a critical detail for translation.19 While powerful, the reliance on external webhooks for validation introduces an operational dependency that may not be suitable for all environments.

### **2.3 Nosey Parker: A Focus on Precision and Testability**

Nosey Parker is a high-performance scanner designed for both offensive and defensive security testing. It emphasizes high-signal, low-noise rules, and its YAML-based format reflects a strong design philosophy centered on precision and maintainability.24

* **Format and Core Components:**
  * **name, id, description:** Standard metadata fields for rule identification.24
  * **pattern:** A single regular expression defines the match. A core design principle of Nosey Parker is that every pattern *must* contain at least one capture group. This forces rule authors to explicitly isolate the sensitive portion of the match from its surrounding context, which is a best practice for reducing ambiguity and improving the quality of findings.24
  * **references:** A required list of URLs or other citations that provide documentation or context for the secret being detected. This is invaluable for analysts who need to understand the significance of a finding.24
  * **examples:** A required list of strings that the rule's pattern *must* match.
  * **negative\_examples:** An optional list of strings that the rule's pattern *must not* match.
* Noteworthy Features and Limitations:
  The mandatory inclusion of examples and the optional negative\_examples directly within the rule definition is a standout feature. This makes the entire rule set self-testing; a simple command (noseyparker rules check) can validate that all rules behave as expected, preventing regressions and ensuring high quality over time.24 The tool leverages the high-performance Hyperscan regex library, which allows it to match all patterns simultaneously in a single pass, making it exceptionally fast on large datasets.25 Its primary limitation is the lack of a formal structure for multi-part secrets or external validation, focusing instead on perfecting high-precision, single-regex matching.

### **2.4 GitHub Secret Scanning: Abstracting Context**

GitHub's native secret scanning service provides a powerful and highly integrated solution. While its custom patterns are configured through a user interface or API rather than a standalone text file, the logical structure of its rules offers important insights into designing a translatable format.26

* **Format and Core Components:**
  * **Pattern name:** A human-readable identifier for the custom pattern.
  * **Secret format:** The core regular expression that describes the structure of the secret itself.
  * **Before secret:** A separate regular expression that defines the pattern of characters that must immediately precede the secret. The default is \\A|\[^0-9A-Za-z\], meaning the secret must be at the start of a line or be preceded by a non-alphanumeric character.28
  * **After secret:** A separate regular expression for the characters that must follow the secret, with a similar default of \\z|\[^0-9A-Za-z\].28
  * **Additional match requirements:** A list of one or more optional regexes that the captured secret string must or must not match. This allows for complex validation logic (e.g., "must contain a digit" and "must not contain two consecutive lowercase letters") without creating an unmanageably complex single regex.28
* Noteworthy Features and Limitations:
  The explicit separation of the secret's pattern from its surrounding context (Before secret and After secret) is a powerful architectural choice. It simplifies rule creation and makes the detection logic more readable and maintainable. This abstraction is a key concept that a universal format should adopt. Like Nosey Parker, GitHub's engine is powered by Hyperscan, meaning its regex syntax is a subset of PCRE and does not support features like lookarounds or backreferences.28 For its vast collection of built-in patterns, GitHub also maintains a partner program where detected secrets can be sent to the relevant service provider for validation and automatic revocation.30

### **2.5 YARA: Expressive Logic for Pattern Matching**

While primarily known as a tool for malware analysis, YARA's flexible and expressive rule language makes it a capable, if unconventional, tool for secret detection. Its strength lies in its ability to define complex logical relationships between multiple patterns.32

* **Format and Core Components:**
  * **meta:** A section for arbitrary key-value metadata, such as description, author, and threat\_level.
  * **strings:** A section where named patterns are defined. Each pattern is given an identifier (e.g., $a, $hex\_string, $regex1). These patterns can be simple text strings, hexadecimal byte sequences, or regular expressions.32 YARA also supports powerful modifiers like
    nocase, wide, ascii, base64, and xor, which are highly relevant for finding secrets that may have been lightly obfuscated.32
  * **condition:** A mandatory boolean expression that constitutes the core logic of the rule. This expression can reference the named strings and use a rich set of operators, including boolean logic (and, or, not), count specifiers (\#a \> 5), file size constraints (filesize \< 1MB), and checks for patterns at specific file offsets ($a at 0).32
* Noteworthy Features and Limitations:
  YARA's primary advantage is the complete decoupling of pattern definition from detection logic. A rule can define a dozen different indicators in the strings section and then use the condition section to express a sophisticated relationship, such as (any of ($keywords)) and ($secret\_pattern) and not ($false\_positive\_indicator). This makes it exceptionally powerful for creating high-fidelity rules that depend on multiple contextual cues. Its main limitation in the secret scanning context is its file-centric nature; it is not inherently designed to scan Git history or other non-standard data sources without external scripting.

### **2.6 Splunk: Detection in Event Streams**

Splunk represents a different class of target system: a log analysis and SIEM platform. It does not scan code directly but is a critical target for detecting secrets that have been exfiltrated or exposed in application logs, command-line histories, or other event data.33

* Format and Core Components:
  Detection rules in Splunk are written in its Search Processing Language (SPL). A typical rule is a query that specifies an index to search, filters events using keywords or field-value pairs, and can use the rex command to apply regular expressions for pattern extraction.33
* Noteworthy Features and Limitations:
  Splunk's unique strength is its ability to perform correlation across vast datasets and over time.37 A "secret detection" rule in Splunk might not be a simple pattern match but a more complex correlation search. For example, a rule could be designed to trigger an alert if a log event containing a
  client\_id is followed within five minutes by another event from the same source IP containing a client\_secret. This stateful, time-based analysis is a fundamentally different paradigm from static file scanning. A universal format must be able to express a basic pattern that can be gracefully degraded into a simple Splunk search, even if it cannot capture the full power of SPL's correlation capabilities.

### **2.7 Bash Utilities (grep): The Lowest Common Denominator**

The grep command and similar command-line utilities represent the most basic form of pattern matching and serve as an essential baseline for translation.38

* Format and Core Components:
  The "rule" is simply a single regular expression pattern passed as a command-line argument.
* Noteworthy Features and Limitations:
  grep has no concept of structured metadata, conditional logic, validation, severity, or confidence. It is a pure pattern-matching engine. Its capabilities are defined by the flags provided (-i for case-insensitivity, \-r for recursive search) and the flavor of regex its implementation supports.
* Relevance:
  Despite its simplicity, grep is a crucial translation target. Any proposed universal format must be reducible to a single regex string. This ensures that the patterns can be used in simple scripts, ad-hoc investigations, and environments where more sophisticated tools are not available. This directly addresses the need for "basic detections" outlined in the project's methodology.

There is a clear evolutionary path visible across these tools. The field is moving from simple, monolithic regex matching toward a more structured, multi-faceted, and context-aware approach. Early methods relied on a single, often complex, regular expression to capture both the secret and its surrounding context.40 More advanced tools began to separate these concerns. Gitleaks introduced

keywords as a simple pre-filter, a nascent form of context separation.14 GitHub formalized this with distinct

before and after patterns, creating a clean separation of concerns.28 Finally, tools like TruffleHog completely decoupled pattern matching from validation by introducing

verify webhooks.19 This progression strongly indicates that a robust generic format must treat these elements—the secret pattern, context patterns, and validation logic—as distinct, first-class components of a rule.

Furthermore, the concept of a "multi-part secret," such as a username/password pair or a client\_id/client\_secret, is a critical detection capability that is inconsistently supported. GitGuardian explicitly mentions support for such "multi-matches".17 TruffleHog achieves this by requiring all named regexes in its

regex map to match, while YARA uses its flexible condition block.19 Other tools lack a formal structure for this, forcing users to attempt it with brittle and hard-to-maintain multi-line regexes. This represents a significant gap that a universal format can address by providing a simple, clear structure for defining these compound secrets, which can then be translated into the best possible equivalent for each target system.

Finally, the maturity of a rule set is often reflected in its testability. Nosey Parker's design, which embeds examples and negative\_examples directly within the rule definition, is a best practice that ensures rules can be automatically and continuously validated.24 This practice directly improves rule quality and maintainability over time, and it is a feature that a universal format should adopt to encourage the creation of high-fidelity, low-noise community rule sets.

| Feature | Gitleaks | TruffleHog | Nosey Parker | GitHub Secret Scanning | YARA | Splunk | grep |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| **Configuration Format** | TOML | YAML | YAML | UI/API (Logical) | Custom (.yar) | SPL Query | Command-line |
| **Primary Pattern Type** | Regex | Regex | Regex | Regex | Regex, Text, Hex | Keywords, Regex | Regex |
| **Regex Engine/Flavor** | Go | Go | Hyperscan | Hyperscan | PCRE-like | PCRE | System-dependent |
| **Contextual Scoping** | Keywords, File Path | Keywords | None | Surrounding Regex | Conditional Logic | Field/Value Pairs | None |
| **Multi-Line Support** | Regex-dependent | Regex-dependent | Regex-dependent | Regex-dependent | Regex-dependent | Event-based | Regex-dependent |
| **Multi-Part Secret Logic** | None | ANDed Regexes | None | None | Conditional Logic | Correlation Search | None |
| **Validation Mechanism** | None | Webhook | None | Partner API | None | None | None |
| **FP Reduction** | Allowlist, Entropy | Exclusions, Entropy | Test Cases | Exclusions | Conditional Logic | Filtering | None |
| **Standard Metadata** | ID, Desc, Tags | Name | ID, Name, Desc, Refs | Name | meta block | N/A | None |

## **Section 3: Core Components of a Universal Detection Pattern**

Drawing from the comparative analysis of existing systems, this section proposes a schema for a universal secret detection pattern. The format is designed to be expressive enough to capture the logic of advanced scanners while remaining translatable to simpler tools. YAML is used for all examples due to its human-readability, support for complex data structures, and its adoption by several modern security tools, including Sigma, TruffleHog, and Nosey Parker.

### **3.1 Foundational Metadata (The "Who" and "Why")**

Clear and comprehensive metadata is the cornerstone of a manageable and collaborative rule set. It provides the essential context for security analysts, rule authors, and automated systems to understand, prioritize, and maintain detections.

* **id**: A globally unique and stable identifier for the rule. Using a Version 4 UUID is recommended to prevent collisions and provide a persistent reference for rule management systems, overrides, and suppression.7
* **name**: A concise, human-readable title for the secret type being detected (e.g., "Amazon Web Services (AWS) Access Key ID").
* **description**: A detailed, multi-line description explaining what the secret is, the potential risks associated with its exposure, and the systems or services it grants access to.
* **author**: The name or handle of the individual or organization that created the rule, essential for attribution and contact.
* **created**: The date of the rule's initial creation, in ISO 8601 format.
* **modified**: The date of the rule's last modification, also in ISO 8601 format. This field should be updated whenever there are significant changes to the detection logic.7
* **references**: A list of URLs pointing to official documentation or authoritative resources that describe the secret's format or function. This provides invaluable context for analysts during incident response.24
* **tags**: A list of arbitrary strings used for categorization and filtering. Tags can be used to group rules by provider (e.g., aws, gcp), secret type (api\_key, database\_credential), or risk category (pii).8

### **3.2 Risk and Confidence Attributes (The "Impact")**

To enable effective prioritization and triage of findings, the format must include fields that quantify the potential impact and reliability of a detection.

* **severity**: An enumerated field that classifies the potential impact of the secret's exposure. A standardized scale, such as informational, low, medium, high, and critical, allows for consistent risk assessment across different rule sets and tools.7
* **confidence**: An enumerated field (low, medium, high) that indicates the rule author's confidence in the pattern's precision. A rule for a highly specific, prefixed key with a checksum would have high confidence, whereas a generic rule for a 32-character hexadecimal string would have low confidence, signaling a higher likelihood of false positives.10

### **3.3 The Detection Block (The "How")**

This is the logical core of the pattern, defining the specific criteria for a match. It is designed as a structured object to separate the various components of detection logic, which is critical for both clarity and translatability.

#### **3.3.1 Matchers (Defining the Patterns)**

A matchers block contains a list of one or more named patterns that the engine will search for.

* **name**: A logical, unique name for the matcher within the rule (e.g., client\_id, secret\_key, username\_field). This name is used in the condition expression.
* **type**: The type of pattern being defined. Common types would include regex, keyword, and hex.
* **pattern**: The pattern string itself.
* **flavor (optional, for regex type)**: A hint specifying the regular expression flavor the pattern was written for (e.g., pcre, hyperscan, go, re2). This is a critical piece of information for the translation engine, allowing it to handle syntactic differences between regex engines and warn the user if a direct translation is not possible.
* **modifiers (optional)**: A list of modifiers that alter the behavior of the matcher, drawing inspiration from YARA's powerful capabilities. Examples include nocase, wide, base64, and xor.32
* **entropy (optional)**: A block to define entropy checks for this specific matcher, with min and max Shannon entropy values. This allows for fine-grained entropy analysis on specific capture groups rather than the entire file.16

#### **3.3.2 Contextual Scoping (Defining the Environment)**

This optional block provides mechanisms to limit the scope of the search, dramatically reducing false positives by ensuring the pattern is found in the correct context.

* **preceded\_by**: A regular expression that must match immediately before the content found by the primary matchers. This is inspired by GitHub's Before secret field.28
* **followed\_by**: A regular expression that must match immediately after the content. This is inspired by GitHub's After secret field.28
* **file\_path\_pattern**: A regular expression that the file path must match for the rule to be applied (e.g., (?i)\\.(env|conf|pem)$).

#### **3.3.3 Conditional Logic (Tying it Together)**

The condition field is a simple but powerful boolean expression that defines the relationship between the named matchers required to trigger a finding. This is the key to expressing multi-part secret logic in a clear and unambiguous way.

* **For a simple secret:** condition: aws\_key
* **For a generic secret with keywords:** condition: (1 of (password\_keywords)) and generic\_secret
* **For a multi-part OAuth secret:** condition: oauth\_client\_id and oauth\_client\_secret

This approach is a simplified but effective adaptation of YARA's condition logic, providing the necessary expressiveness for complex detections.32

### **3.4 Validation Block (The "Is it Real?")**

This optional block defines a method for actively validating a potential secret after it has been detected, a feature pioneered by tools like TruffleHog.

* **type**: The validation method to be used. Initial types could include webhook, checksum, and luhn.
* **endpoint**: For webhook validation, this specifies the URL to which the finding should be sent for verification.19
* **algorithm**: For checksum validation, this specifies the algorithm to be used (e.g., mod11).
* **capture\_groups**: A list specifying which named capture groups from the matchers should be extracted and sent to the validator.

### **3.5 Supporting Data (The "Test Cases")**

To promote the creation of high-quality, low-noise rules, the format should directly incorporate test cases, a practice championed by Nosey Parker.24

* **examples**: A list of strings that represent true positives. The rule *must* match every entry in this list.
* **negative\_examples**: A list of strings that represent known false positives. The rule *must not* match any entry in this list.

This structured approach creates an implicit hierarchy of detection fidelity. A basic rule might only define a single matcher and a simple condition. A more advanced rule can add contextual scoping, and a high-fidelity rule can incorporate complex multi-part logic and an automated validation step. This layered design directly addresses the need to support tools with varying capabilities, providing a robust framework for graceful degradation during translation.

## **Section 4: Architectural Considerations for a Translation Engine**

The universal pattern format, while essential, is only one half of the solution. Its practical value is entirely dependent on the existence of a robust and intelligent translation engine—a "compiler" that can convert a generic pattern into the native rule format of a specific target tool. This section outlines the architectural principles and key challenges in building such a translator.

### **4.1 Core Translation Logic: The "Graceful Degradation" Principle**

The central design philosophy for the translation engine must be "graceful degradation." Not all target tools support the same set of features. A sophisticated rule with multi-part logic and webhook validation cannot be translated with 1:1 fidelity to a simple tool like grep. The translator's goal is to produce the most accurate possible rule for the target system, even if it means losing some of the original rule's fidelity. It should always produce a usable output and clearly communicate which features were dropped in the process.

* **Example Translation Flow (Generic Rule to grep):**
  1. **Parse:** The engine parses the generic YAML rule file.
  2. **Identify Primary Pattern:** It identifies the pattern from the most significant matcher in the condition (e.g., the matcher named secret\_value).
  3. **Combine Context (Best Effort):** If preceded\_by or followed\_by patterns exist, the engine attempts to concatenate them into a single, larger regex. This is a best-effort conversion and may not always be possible or efficient.
  4. **Ignore Unsupported Features:** All other structured information—metadata (id, severity), multi-part logic, validation blocks, and test cases—is discarded for this target.
  5. **Output:** The engine outputs the final, single regular expression string.
  6. **Warn:** Crucially, the engine should print a warning to the standard error stream, informing the user that features like validation and multi-part logic were dropped during the translation to grep.
* **Example Translation Flow (Generic Rule to TruffleHog):**
  1. **Parse:** The engine parses the generic YAML rule.
  2. **Map Metadata:** The generic id or name is mapped to TruffleHog's name field.
  3. **Translate Multi-Part Logic:** A condition like client\_id and client\_secret is translated into TruffleHog's regex block as a map with two named regexes, client\_id and client\_secret. This is a high-fidelity translation of the multi-part logic.
  4. **Translate Validation:** The generic validation block is translated directly into TruffleHog's verify block, mapping the endpoint and headers.
  5. **Output:** The engine generates a complete and valid YAML configuration snippet for a TruffleHog custom detector.

### **4.2 Handling Feature Mismatches**

The primary technical challenge in translation is navigating the semantic and syntactic gaps between different systems.4

* **Semantic Gaps:** Some concepts are fundamentally untranslatable. For example, a YARA rule that relies on matching a pattern at a specific file offset ($a at 0\) cannot be accurately represented in a line-based scanner like Gitleaks. The translation engine must be intelligent enough to identify these impossible mappings. In such cases, it should fail with a clear, descriptive error message explaining why the rule cannot be translated to the target, rather than producing a silent, incorrect rule.
* **Regex Flavor Conversion:** Regular expression engines are not standardized. A pattern written for PCRE might use features like lookarounds or backreferences that are not supported by the Hyperscan engine used in GitHub and Nosey Parker.28 The translation engine should incorporate a regex "transpiler" library capable of converting between common flavors. When an unsupported feature is encountered, the engine should first attempt to rewrite the expression to be compatible. If this is not possible, it should fall back to a simpler version of the regex and warn the user about the loss of specificity. The
  flavor hint in the generic format is critical for guiding this process.

### **4.3 The Translator as a Command-Line Tool**

To maximize utility and integration with developer workflows, the translation engine should be implemented as a command-line tool, analogous to sigmac. A potential command structure would be:

secrets-compiler \-t \<target\_format\> \-o \<output\_file\_or\_dir\> \<input\_rule\_file\_or\_dir\>

* \-t, \--target: Specifies the output format (e.g., gitleaks, trufflehog, noseyparker, yara, github-json, grep, splunk-spl).
* \-o, \--output: Specifies the destination for the translated rule(s).
* input: The path to one or more generic rule files to be translated.

### **4.4 Integration with a Central Rule Repository**

Drawing another lesson from the Sigma project, the translator tool should be designed to integrate seamlessly with a central, community-maintained Git repository of rules. This would allow users to easily keep their local rule sets up-to-date. The tool could include subcommands for managing this repository:

secrets-compiler update
secrets-compiler list-rules \--tag aws
This functionality would lower the barrier to entry for users and encourage the growth of a rich, shared ecosystem of high-quality detection patterns.

## **Section 5: Recommendations and Path Forward**

This report has established the need for a universal secret detection format, analyzed the capabilities of existing tools, and proposed a comprehensive schema and translation architecture. The following recommendations provide an actionable roadmap for the Special Interest Group to begin the development and implementation of this framework.

### **5.1 Proposed Vocabulary and Glossary**

To ensure clear and consistent communication throughout the project, it is essential to establish a formal glossary of terms. This will form the foundation of the standard's documentation.

* **Pattern:** The top-level object representing a single secret detection rule in the universal format.
* **Matcher:** A named component within a Pattern that defines a specific string, regex, or hex sequence to be searched for.
* **Condition:** The boolean expression within a Pattern that defines the logical relationship between Matchers required to trigger a Finding.
* **Context:** The set of attributes within a Pattern that scope the detection to a specific environment, such as file paths or surrounding text patterns.
* **Validation:** An optional, active step defined within a Pattern to verify if a potential secret is live, typically via an API call or checksum.
* **Finding:** A specific instance of a matched Pattern within a scanned asset.
* **High-Fidelity:** A quality of detection characterized by high precision (low false positives) and high recall (low false negatives), often achieved through the use of Context, multi-part logic, and Validation.

### **5.2 Phased Implementation Roadmap**

A phased approach is recommended to ensure the project delivers value incrementally and incorporates community feedback at each stage.

* **Phase 1: Format Ratification (1-2 Months)**
  * **Objective:** To finalize and formally adopt Version 1.0 of the generic YAML schema.
  * **Activities:**
    * Conduct a series of working sessions within the SIG to review and refine the proposed schema from Section 3\.
    * Publish a draft specification for public comment from the broader security community.
    * Incorporate feedback and publish the final V1.0 specification.
* **Phase 2: Proof-of-Concept Translator (3-4 Months)**
  * **Objective:** To develop the initial secrets-compiler tool and prove the viability of the translation concept.
  * **Activities:**
    * Implement the core parsing and translation logic.
    * Develop translator backends for two diverse targets to demonstrate the graceful degradation principle: one high-fidelity target (e.g., TruffleHog) and one low-fidelity target (e.g., grep).
    * Develop a test suite for the translator using the examples and negative\_examples from a set of sample rules.
* **Phase 3: Community Rule Development (Ongoing)**
  * **Objective:** To establish a public, community-driven repository of high-quality rules written in the new universal format.
  * **Activities:**
    * Create a public Git repository with a clear contribution guide and CI/CD pipeline for rule validation.
    * Seed the repository by porting an initial set of 20-30 high-quality, high-confidence rules from existing open-source tools (e.g., Gitleaks, Nosey Parker).
    * Promote the repository to the security community to encourage contributions.
* **Phase 4: Expanded Translator Support (Ongoing)**
  * **Objective:** To incrementally increase the utility of the universal format by adding support for more target systems.
  * **Activities:**
    * Prioritize and develop translator backends for the remaining target tools identified in this report: Gitleaks, Nosey Parker, YARA, GitHub Secret Scanning, and Splunk.
    * Engage with the maintainers of these open-source tools to ensure the generated rules are accurate and optimized.

### **5.3 Call to Action**

The creation of a universal standard for secret detection is an ambitious but achievable goal. Its success, however, does not depend solely on the technical merits of the format or its translator, but on the engagement and adoption of the security community. This report provides the technical foundation and strategic roadmap, but the true potential of this initiative will only be realized through collaborative effort. The SIG is encouraged to share this work widely and to invite contributions from researchers, tool developers, and security practitioners. By working together to build a shared language for describing secrets, the community can create a more interoperable, efficient, and ultimately more secure ecosystem for everyone.

#### **Works cited**

1. TruffleHog vs. Gitleaks: A Detailed Comparison of Secret Scanning Tools \- Jit.io, accessed July 27, 2025, [https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools](https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools)
2. Secure Code Scanning: Basics & Best Practices \- Wiz, accessed July 27, 2025, [https://www.wiz.io/academy/code-scanning](https://www.wiz.io/academy/code-scanning)
3. Secrets Detection: A Fast-Track Guide \- Wiz, accessed July 27, 2025, [https://www.wiz.io/academy/secrets-detection](https://www.wiz.io/academy/secrets-detection)
4. Cross-Platform Rule Translation: From Sigma to CrowdStrike with ..., accessed July 27, 2025, [https://socprime.com/blog/cross-platform-rule-translation-from-sigma-to-crowdstrike-with-uncoder-ai/](https://socprime.com/blog/cross-platform-rule-translation-from-sigma-to-crowdstrike-with-uncoder-ai/)
5. Sigma Rules: Your Guide to Threat Detection's Open Standard \- Panther Labs, accessed July 27, 2025, [https://panther.com/blog/your-guide-to-the-sigma-rules-open-standard-for-threat-detection](https://panther.com/blog/your-guide-to-the-sigma-rules-open-standard-for-threat-detection)
6. What are Sigma rules? \- Comcast Technology Solutions, accessed July 27, 2025, [https://www.comcasttechnologysolutions.com/what-are-sigma-rules](https://www.comcasttechnologysolutions.com/what-are-sigma-rules)
7. Rules | Sigma Detection Format, accessed July 27, 2025, [https://sigmahq.io/docs/basics/rules.html](https://sigmahq.io/docs/basics/rules.html)
8. Sigma rules\! The generic signature format for SIEM systems. \- SANS Internet Storm Center, accessed July 27, 2025, [https://isc.sans.edu/diary/26258](https://isc.sans.edu/diary/26258)
9. What Are Sigma Rules? \- Picus Security, accessed July 27, 2025, [https://www.picussecurity.com/resource/glossary/what-is-sigma-rule](https://www.picussecurity.com/resource/glossary/what-is-sigma-rule)
10. Secrets Patterns DB: The largest open-source Database for ... \- GitHub, accessed July 27, 2025, [https://github.com/mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db)
11. Secrets Detection and Scanning by Cycode, accessed July 27, 2025, [https://cycode.com/hard-coded-secrets-detection/](https://cycode.com/hard-coded-secrets-detection/)
12. What Is Secrets Detection? Preventing Credential Exposure | Orca ..., accessed July 27, 2025, [https://orca.security/glossary/secrets-detection/](https://orca.security/glossary/secrets-detection/)
13. Gitleaks step configuration \- Harness Developer Hub, accessed July 27, 2025, [https://developer.harness.io/docs/security-testing-orchestration/sto-techref-category/gitleaks-scanner-reference/](https://developer.harness.io/docs/security-testing-orchestration/sto-techref-category/gitleaks-scanner-reference/)
14. Custom rulesets schema \- GitLab Docs, accessed July 27, 2025, [https://docs.gitlab.com/user/application\_security/secret\_detection/pipeline/custom\_rulesets\_schema/](https://docs.gitlab.com/user/application_security/secret_detection/pipeline/custom_rulesets_schema/)
15. Custom rulesets schema | GitLab Docs, accessed July 27, 2025, [https://docs.gitlab.com/ee/user/application\_security/secret\_detection/pipeline/custom\_rulesets\_schema.html](https://docs.gitlab.com/ee/user/application_security/secret_detection/pipeline/custom_rulesets_schema.html)
16. custom-gitleaks-rules.toml \- GitHub Gist, accessed July 27, 2025, [https://gist.github.com/davidsalvador-tf/6867803105e0bab05b8a83ecd3fec619](https://gist.github.com/davidsalvador-tf/6867803105e0bab05b8a83ecd3fec619)
17. Secrets Detection Engine | GitGuardian documentation, accessed July 27, 2025, [https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/quick\_start](https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/quick_start)
18. gitleaks/gitleaks: Find secrets with Gitleaks \- GitHub, accessed July 27, 2025, [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
19. Custom detectors \- TruffleHog Docs, accessed July 27, 2025, [https://docs.trufflesecurity.com/custom-detectors](https://docs.trufflesecurity.com/custom-detectors)
20. TruffleHog \- A Deep Dive on Secret Management and How to Fix Exposed Secrets \- Jit.io, accessed July 27, 2025, [https://www.jit.io/resources/appsec-tools/trufflehog-a-deep-dive-on-secret-management-and-how-to-fix-exposed-secrets](https://www.jit.io/resources/appsec-tools/trufflehog-a-deep-dive-on-secret-management-and-how-to-fix-exposed-secrets)
21. Rooting For Secrets with TruffleHog \- Black Hills Information Security, Inc., accessed July 27, 2025, [https://www.blackhillsinfosec.com/rooting-for-secrets-with-trufflehog/](https://www.blackhillsinfosec.com/rooting-for-secrets-with-trufflehog/)
22. trufflehog \- CT Stack 安全社区, accessed July 27, 2025, [https://stack.chaitin.com/tool/detail/146](https://stack.chaitin.com/tool/detail/146)
23. trufflesecurity/trufflehog: Find, verify, and analyze leaked credentials \- GitHub, accessed July 27, 2025, [https://github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)
24. Nosey Parker Rules \- GitHub, accessed July 27, 2025, [https://github.com/praetorian-inc/noseyparker/blob/main/docs/RULES.md](https://github.com/praetorian-inc/noseyparker/blob/main/docs/RULES.md)
25. Nosey Parker, a fast and low-noise secrets detector for textual data \- Hacker News, accessed July 27, 2025, [https://news.ycombinator.com/item?id=35004184](https://news.ycombinator.com/item?id=35004184)
26. Managing custom patterns \- GitHub Enterprise Cloud Docs, accessed July 27, 2025, [https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/custom-patterns/managing-custom-patterns](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/custom-patterns/managing-custom-patterns)
27. Custom patterns \- GitHub Docs, accessed July 27, 2025, [https://docs.github.com/en/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/custom-patterns](https://docs.github.com/en/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/custom-patterns)
28. Defining custom patterns for secret scanning \- GitHub Enterprise Cloud Docs, accessed July 27, 2025, [https://docs.github.com/enterprise-cloud@latest/code-security/secret-scanning/defining-custom-patterns-for-secret-scanning](https://docs.github.com/enterprise-cloud@latest/code-security/secret-scanning/defining-custom-patterns-for-secret-scanning)
29. Defining custom patterns for secret scanning \- GitHub Enterprise ..., accessed July 27, 2025, [https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/defining-custom-patterns-for-secret-scanning](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/defining-custom-patterns-for-secret-scanning)
30. About secret scanning \- GitHub Docs, accessed July 27, 2025, [https://docs.github.com/code-security/secret-scanning/about-secret-scanning](https://docs.github.com/code-security/secret-scanning/about-secret-scanning)
31. Supported secret scanning patterns \- GitHub Docs, accessed July 27, 2025, [https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns](https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns)
32. Writing YARA rules — yara 4.4.0 documentation, accessed July 27, 2025, [https://yara.readthedocs.io/en/stable/writingrules.html](https://yara.readthedocs.io/en/stable/writingrules.html)
33. Splunk Search Collector \- Cribl Docs, accessed July 27, 2025, [https://docs.cribl.io/stream/collectors-splunk-search](https://docs.cribl.io/stream/collectors-splunk-search)
34. Detections | Splunk Security Content, accessed July 27, 2025, [https://research.splunk.com/detections/](https://research.splunk.com/detections/)
35. Scanning Splunk data for secret leaking?, accessed July 27, 2025, [https://community.splunk.com/t5/Security/Scanning-Splunk-data-for-secret-leaking/td-p/633530](https://community.splunk.com/t5/Security/Scanning-Splunk-data-for-secret-leaking/td-p/633530)
36. How do I create a search which detects password changes and finds the last time the password was changed? \- Splunk Community, accessed July 27, 2025, [https://community.splunk.com/t5/Splunk-Enterprise-Security/How-do-I-create-a-search-which-detects-password-changes-and/m-p/435168](https://community.splunk.com/t5/Splunk-Enterprise-Security/How-do-I-create-a-search-which-detects-password-changes-and/m-p/435168)
37. Splexicon:Correlationsearch \- Splunk Documentation, accessed July 27, 2025, [https://docs.splunk.com/Splexicon:Correlationsearch](https://docs.splunk.com/Splexicon:Correlationsearch)
38. Developer essentials: How to search code using grep | MDN Blog, accessed July 27, 2025, [https://developer.mozilla.org/en-US/blog/searching-code-with-grep/](https://developer.mozilla.org/en-US/blog/searching-code-with-grep/)
39. Linux find and grep command together \- Stack Overflow, accessed July 27, 2025, [https://stackoverflow.com/questions/21763904/linux-find-and-grep-command-together](https://stackoverflow.com/questions/21763904/linux-find-and-grep-command-together)
40. Help Find and Remove Hard Coded Passwords and Secrets in a Project \- Nick Janetakis, accessed July 27, 2025, [https://nickjanetakis.com/blog/help-find-and-remove-hard-coded-passwords-and-secrets-in-a-project](https://nickjanetakis.com/blog/help-find-and-remove-hard-coded-passwords-and-secrets-in-a-project)
41. Mastering grep Regex: Unlock Efficient Text Search Secrets \- Tah Computing Solutions, accessed July 27, 2025, [https://ktah.cs.lmu.edu/grep-regex](https://ktah.cs.lmu.edu/grep-regex)
42. Advanced Regular Expressions in Grep Command with 10 Examples – Part II, accessed July 27, 2025, [https://www.thegeekstuff.com/2011/01/advanced-regular-expressions-in-grep-command-with-10-examples-%E2%80%93-part-ii/](https://www.thegeekstuff.com/2011/01/advanced-regular-expressions-in-grep-command-with-10-examples-%E2%80%93-part-ii/)
43. Create a detection rule | Elastic Docs, accessed July 27, 2025, [https://www.elastic.co/docs/solutions/security/detect-and-alert/create-detection-rule](https://www.elastic.co/docs/solutions/security/detect-and-alert/create-detection-rule)
44. Best practices for migrating detection rules from ArcSight, Splunk and QRadar to Azure Sentinel | Microsoft Community Hub, accessed July 27, 2025, [https://techcommunity.microsoft.com/blog/microsoftsentinelblog/best-practices-for-migrating-detection-rules-from-arcsight-splunk-and-qradar-to-/2216417](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/best-practices-for-migrating-detection-rules-from-arcsight-splunk-and-qradar-to-/2216417)
45. Why Detection Rules Fail: Causes, Effects, and Corrective Actions \- Picus Security, accessed July 27, 2025, [https://www.picussecurity.com/resource/blog/why-detection-rules-fail](https://www.picussecurity.com/resource/blog/why-detection-rules-fail)
