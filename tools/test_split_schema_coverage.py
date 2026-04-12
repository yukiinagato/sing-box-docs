#!/usr/bin/env python3
import json
import re
import html
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configuration"
SCHEMA_DIR = ROOT / "generated" / "configuration-schemas"


def clean_html(t: str) -> str:
    t = re.sub(r"<[^>]+>", "", t)
    return html.unescape(t).strip()


def article(path: Path) -> str:
    s = path.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r'<article class="md-content__inner md-typeset">(.*?)</article>', s, re.S)
    return m.group(1) if m else s


def collect_expected_h4():
    expected = {}
    for html_file in sorted(CONFIG.glob("**/index.html")):
        rel = str(html_file.relative_to(ROOT))
        if rel == "configuration/index.html":
            continue
        a = article(html_file)
        h4 = [clean_html(x) for x in re.findall(r'<h4 id="[^"]+">(.*?)</h4>', a, re.S)]
        expected[rel] = h4
    return expected


def collect_enum_expectations():
    """Collect fields whose source prose indicates explicit enum values."""
    expected = {}
    for html_file in sorted(CONFIG.glob("**/index.html")):
        rel = str(html_file.relative_to(ROOT))
        if rel == "configuration/index.html":
            continue
        a = article(html_file)
        h4_matches = list(re.finditer(r'<h4 id="[^"]+">(.*?)</h4>', a, re.S))
        page_expect = set()
        for i, m in enumerate(h4_matches):
            field = clean_html(m.group(1))
            start = m.end()
            end = h4_matches[i + 1].start() if i + 1 < len(h4_matches) else len(a)
            block = clean_html(a[start:end])
            if "Available values" in block or re.search(r"One of:?\s+[^\.\n]+", block, re.I):
                page_expect.add(field)
        expected[rel] = page_expect
    return expected


def collect_actual_fields():
    actual = {}
    actual_allowed = {}
    for jf in sorted(SCHEMA_DIR.glob("*.json")):
        data = json.loads(jf.read_text(encoding="utf-8"))
        for page in data.get("pages", []):
            src = page.get("source_path")
            if not src:
                continue
            fields = page.get("fields", {})
            actual[src] = set(fields.keys())
            actual_allowed[src] = {
                k for k, v in fields.items()
                if isinstance(v, dict) and isinstance(v.get("allowedValues"), list) and len(v["allowedValues"]) > 0
            }
    return actual, actual_allowed


def main():
    expected = collect_expected_h4()
    enum_expected = collect_enum_expectations()
    actual, actual_allowed = collect_actual_fields()

    total = 0
    covered = 0
    missing_items = []
    missing_pages = []

    for src, fields in expected.items():
        if src not in actual:
            missing_pages.append(src)
            total += len(fields)
            continue
        actual_fields = actual[src]
        for f in fields:
            total += 1
            if f in actual_fields:
                covered += 1
            else:
                missing_items.append((src, f))

    coverage = 100.0 if total == 0 else (covered * 100.0 / total)
    print(f"coverage: {coverage:.2f}% ({covered}/{total})")

    if missing_pages:
        print("missing schema pages:")
        for p in missing_pages[:100]:
            print(" -", p)

    if missing_items:
        print("missing fields:")
        for src, f in missing_items[:200]:
            print(f" - {src}: {f}")

    enum_missing = []
    for src, fields in enum_expected.items():
        available_fields = actual_allowed.get(src, set())
        for f in fields:
            if f not in available_fields:
                enum_missing.append((src, f))

    if enum_missing:
        print("missing allowedValues for enum-like prose:")
        for src, f in enum_missing[:200]:
            print(f" - {src}: {f}")

    if coverage < 100.0 or missing_pages or missing_items or enum_missing:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
