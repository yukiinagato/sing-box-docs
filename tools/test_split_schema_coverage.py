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


def collect_actual_fields():
    actual = {}
    for jf in sorted(SCHEMA_DIR.glob("*.json")):
        data = json.loads(jf.read_text(encoding="utf-8"))
        for page in data.get("pages", []):
            src = page.get("source_path")
            if not src:
                continue
            actual[src] = set(page.get("fields", {}).keys())
    return actual


def main():
    expected = collect_expected_h4()
    actual = collect_actual_fields()

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

    if coverage < 100.0 or missing_pages or missing_items:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
