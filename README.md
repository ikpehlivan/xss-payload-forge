\# XSS Payload Forge



A lightweight Burp-like \*\*XSS payload generator\*\* that produces:

\- Baseline reflected XSS payload templates

\- Heuristic WAF-bypass variations

\- Encoding variants (URL, double URL, HTML entities)



This tool \*\*only generates payload strings\*\* and does not perform scanning or exploitation.



---



\## ⚠️ Disclaimer



For \*\*authorized security testing and educational purposes only\*\*.

Always validate results manually in the correct injection context.

The author assumes no responsibility for misuse.



---



\## Features



\### 1) Reflected XSS Baseline Payloads

Generates common reflected-XSS payload templates designed to fit typical HTML/attribute contexts.



\### 2) Heuristic WAF-Bypass Variations

Applies simple mutation strategies such as:

\- Random casing

\- HTML comment splitting

\- Whitespace obfuscation

\- Legacy-style null-byte-like patterns

\- Prefix/suffix wrappers for context breaking



> Note: These are heuristic techniques. Real WAF bypassing depends on context, parsing quirks, and target-side filtering.



\### 3) Encoding Combinations

Produces encoded variants:

\- URL-encoding

\- Double URL-encoding

\- Basic HTML entity encoding



---



\## Project Structure

xss-payload-forge/

xss\_forge.py

requirements.txt

README.md



---

No external dependencies required (Python 3.10+ recommended).



---



\## Usage



\### Generate payloads (default)

python xss\_forge.py



Generate and print to stdout

python xss\_forge.py --print



Reproducible output with a seed

python xss\_forge.py --seed 1337



Disable WAF variants

python xss\_forge.py --no-waf



Disable encodings

python xss\_forge.py --no-enc



Output to a custom file

python xss\_forge.py -o my\_payloads.json



Output



The tool generates a JSON file:



meta.marker: a unique marker string embedded into payloads (useful for reflection tracking)



payloads\[]: each payload includes category, mutation type, encoding type, and a short note



Example:



{

&nbsp; "category": "waf\_variant",

&nbsp; "variant": "html\_comments",

&nbsp; "encoding": "url",

&nbsp; "payload": "%22%3E%3Csv%3C!--x--%3Eg%2Fonlo%3C!--x--%3Ead%3Dalert%28%22Xabc123%22%29%3E",

&nbsp; "note": "Heuristic WAF-evasion style mutation (manual validation required)"

}





Why This Project?

This repository demonstrates practical offensive security knowledge:

Understanding reflected XSS contexts

Building payload sets for manual testing workflows

Producing structured, reproducible output for tooling integration

