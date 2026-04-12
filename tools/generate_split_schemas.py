#!/usr/bin/env python3
import json
import re
import html
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "configuration"
OUT_DIR = ROOT / "generated" / "configuration-schemas"


def read_article(path: Path) -> str:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r'<article class="md-content__inner md-typeset">(.*?)</article>', raw, re.S)
    return m.group(1) if m else raw


def clean_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def infer_type(field: str, context: str) -> str:
    n = field.lower()
    c = context.lower()
    if any(k in n for k in ["enabled", "disable", "strict", "allow", "reject", "debug", "sniff", "fragment", "tls", "insecure"]):
        return "boolean"
    if any(k in n for k in ["port", "mtu", "timeout", "interval", "mark", "id", "ttl", "length"]) and not n.endswith("s"):
        return "integer"
    if any(k in n for k in ["addresses", "ports", "hosts", "names", "rules", "servers", "users", "paths"]):
        if "port" in n:
            return "array_integer"
        return "array_object"
    if "array" in c or "list" in c:
        return "array_object"
    if "configuration" in c or "options" in c:
        return "object"
    return "string"


def parse_dependencies(text: str):
    deps = []

    for m in re.findall(r"Conflict with\s+([^\.]+)", text, re.I):
        for p in re.split(r",| and ", m):
            f = p.strip(" `")
            if f:
                deps.append({"type": "conflicts_with", "field": f})

    for m in re.findall(r"Only available with\s+([^\.]+)", text, re.I):
        f = m.strip(" `")
        if f:
            deps.append({"type": "requires", "field": f})

    for m in re.findall(r"Required (?:when|if)\s+([^\.]+)", text, re.I):
        expr = m.strip(" `")
        if expr:
            deps.append({"type": "required_if", "expression": expr})

    return deps


def parse_page(path: Path):
    article = read_article(path)
    title_m = re.search(r"<h1[^>]*>(.*?)</h1>", article, re.S)
    title = clean_html(title_m.group(1)) if title_m else path.parent.name

    page = {
        "page_id": path.parent.name,
        "source_path": str(path.relative_to(ROOT)),
        "title": title,
        "fields": {},
        "section_titles": []
    }

    # capture section titles h3 for traceability
    for h3 in re.findall(r"<h3 id=\"[^\"]+\">(.*?)</h3>", article, re.S):
        page["section_titles"].append(clean_html(h3))

    h4_matches = list(re.finditer(r"<h4 id=\"[^\"]+\">(.*?)</h4>", article, re.S))
    for i, m in enumerate(h4_matches):
        field = clean_html(m.group(1))
        start = m.end()
        end = h4_matches[i + 1].start() if i + 1 < len(h4_matches) else len(article)
        block = article[start:end]
        text = clean_html(block)

        data = {
            "type": infer_type(field, text),
            "required": "<mark>Required</mark>" in block,
        }

        av = []
        for m_av in re.finditer(r"Available values:\s*</p>\s*<ul>(.*?)</ul>", block, re.S):
            vals = re.findall(r"<li>(.*?)</li>", m_av.group(1), re.S)
            for v in vals:
                cv = clean_html(v)
                if cv:
                    av.append(cv)
        if av:
            data["allowedValues"] = av

        dm = re.search(r"(?:Default(?:s to| value)?):\s*([^\.]+)", text, re.I)
        if dm:
            d = dm.group(1).strip(" `\"")
            if d.lower() in ("true", "false"):
                data["default"] = d.lower() == "true"
            elif re.fullmatch(r"-?\d+", d):
                data["default"] = int(d)
            else:
                data["default"] = d

        deps = parse_dependencies(text)
        if deps:
            data["dependencies"] = deps

        sm = re.findall(r"Since sing-box\s+([0-9.]+)", text)
        if sm:
            data["since"] = sm[-1]

        if "Deprecated in sing-box" in text:
            data["deprecated"] = True

        desc = ""
        for sentence in re.split(r"(?<=[.!?])\s+", text):
            s = sentence.strip()
            if not s:
                continue
            if s.startswith("Available values") or s.startswith("Default") or s.startswith("Since sing-box") or s == "Required":
                continue
            desc = s
            break
        if desc:
            data["description"] = desc

        page["fields"][field] = data

    return page


def build_module(module_dir: Path):
    module_name = module_dir.name

    pages = []
    for idx in sorted(module_dir.glob("**/index.html")):
        pages.append(parse_page(idx))

    output = {
        "module": module_name,
        "source": str(module_dir.relative_to(ROOT)),
        "page_count": len(pages),
        "pages": pages,
    }
    return output


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    modules = [d for d in sorted(CONFIG_DIR.iterdir()) if d.is_dir()]

    for module_dir in modules:
        module_json = build_module(module_dir)
        out_path = OUT_DIR / f"{module_dir.name}.json"
        out_path.write_text(json.dumps(module_json, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"generated: {out_path}")


if __name__ == "__main__":
    main()
