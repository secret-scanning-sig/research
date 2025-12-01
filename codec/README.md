# Codec

**This is currently a DRAFT project.**

## Goal

Describe an algorithm that can:

- Detect encoded substrings in a string 
- Replace encoded substrings with their decoded values
- Decode encoded substrings that overlap or are contained in previously decoded substrings 
- Map a decoded substring's position to its encoded position the original string 
- Be performant enough to enable by default in most scenarios

Describe approaches like the following for scanning the resulting string(s) for secrets:

- Only scanning the fully decoded string 
- Scanning the string at each layer of decoding 
  - Without double reporting findings
  - Why this might be desirable

Describe it in a way that it can be integrated into different scanners.

Because things like:
[intentional obfuscation by malware](https://thehackernews.com/2025/11/second-sha1-hulud-wave-affects-25000.html), 
[tools requiring encoded values](https://kubernetes.io/docs/concepts/configuration/secret/),
[formatting codes](https://en.wikipedia.org/wiki/ANSI_escape_code),
[partial encodings](https://en.wikipedia.org/wiki/Percent-encoding),
etc make pure regex secret detection difficult or impossible.

## Last Updated

2025-11-30

## Methodology

**In-Progress**

Rough plan:

- [ ] Provide an overview of [prior work](https://github.com/gitleaks/gitleaks/tree/6eaad0/detect/codec)
- [ ] Describe the algorithm here 
- [ ] Set up an initial reference implementation from the prior work
- [ ] Benchmark and record the results of the initial reference implementation
- [ ] Go through several iterations of improving the algorithm
- [ ] Finish out some reference implementations (Go, Rust, Python, C)
- [ ] Benchmark and tune those more
- [ ] Write up results & conclusion

## Results & Conclusion

**Pending: work above**

To Add:

- [ ] Summary of the above
- [ ] Benchmark results
- [ ] Notes about inclusion in other scanners
