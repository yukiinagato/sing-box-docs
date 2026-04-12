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


def parse_one_of_values(text: str):
    values = []
    # Pattern examples:
    # - One of: trace debug info warn error fatal panic.
    # - One of prefer_ipv4 prefer_ipv6 ipv4_only ipv6_only.
    # - One of `a`, `b`, `c`.
    for m in re.findall(r"One of:?\s*([^\.]+)", text, re.I):
        if "is required if" in m.lower():
            # this is a conditional requirement sentence, not enum candidates
            continue
        raw = m.strip().strip("`")
        code_values = [x.strip(" `") for x in re.findall(r"`([^`]+)`", raw)]
        if code_values:
            parts = code_values
        # support comma-separated and space-separated enumerations
        elif "," in raw:
            parts = [x.strip(" `") for x in raw.split(",")]
        else:
            parts = [x.strip(" `") for x in raw.split()]
        for p in parts:
            p = re.sub(r"^(or|and)\s+", "", p, flags=re.I).strip(" `")
            if p and p.lower() not in {"or", "and"}:
                values.append(p)
    return values


def parse_complex_requirements(text: str):
    """Extract structured conditional requirements from prose.

    Example:
    One of client_certificate, client_certificate_path, or
    client_certificate_public_key_sha256 is required if this option is set to
    verify-if-given, or require-and-verify.
    """
    rules = []
    pattern = re.compile(
        r"One of\s+(.+?)\s+is required if this option is set to\s+([^\.]+)",
        re.I,
    )
    for m in pattern.finditer(text):
        lhs, rhs = m.group(1), m.group(2)

        def _normalize_token(token: str) -> str:
            token = token.strip(" `")
            token = re.sub(r"^(or|and)\s+", "", token, flags=re.I)
            return token.strip(" `")

        fields = [
            _normalize_token(f)
            for f in re.split(r",\s*|\s+or\s+|\s+and\s+", lhs)
            if _normalize_token(f)
        ]
        values = [
            _normalize_token(v)
            for v in re.split(r",\s*|\s+or\s+|\s+and\s+", rhs)
            if _normalize_token(v)
        ]

        if fields and values:
            rules.append(
                {
                    "type": "conditional_one_of_required",
                    "when": {
                        "field": "this",
                        "operator": "in",
                        "value": values,
                    },
                    "oneOfRequired": fields,
                    "exactlyOne": True,
                }
            )
    return rules


def parse_page(path: Path):
    article = read_article(path)
    title_m = re.search(r"<h1[^>]*>(.*?)</h1>", article, re.S)
    title = clean_html(title_m.group(1)) if title_m else path.parent.name

    page = {
        "page_id": path.parent.name,
        "source_path": str(path.relative_to(ROOT)),
        "title": title,
        "fields": {},
        "section_titles": [],
        "validations": [],
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
        # Pattern A: list style after paragraph: "Available values:" + <ul>...</ul>
        for m_av in re.finditer(r"Available values(?: are|, also the default list)?:\s*</p>\s*<ul>(.*?)</ul>", block, re.S):
            vals = re.findall(r"<li>(.*?)</li>", m_av.group(1), re.S)
            for v in vals:
                cv = clean_html(v)
                if cv:
                    av.append(cv)
        # Pattern B: inline paragraph: "Available values: <code>a</code>, <code>b</code> ..."
        for m_av_inline in re.finditer(r"Available values(?: are|, also the default list)?:\s*(.*?)</p>", block, re.S):
            inline = m_av_inline.group(1)
            code_vals = [clean_html(v) for v in re.findall(r"<code>(.*?)</code>", inline, re.S)]
            if code_vals:
                av.extend([v for v in code_vals if v])
            else:
                raw_inline = clean_html(inline)
                for part in re.split(r",|\s+and\s+", raw_inline):
                    p = part.strip(" `")
                    if p:
                        av.append(p)
        if av:
            data["allowedValues"] = sorted(set(av))

        extra_allowed = parse_one_of_values(text)
        if extra_allowed:
            data["allowedValues"] = sorted(set(data.get("allowedValues", []) + extra_allowed))

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

        complex_rules = parse_complex_requirements(text)
        if complex_rules:
            # bind rule to current field ("this" => current field name)
            for rule in complex_rules:
                rule["field"] = field
                rule["when"]["field"] = field
                page["validations"].append(rule)

                # expose dependency shortcut at field level as well
                data.setdefault("dependencies", []).append(
                    {
                        "type": "conditional_exactly_one_required",
                        "when": rule["when"],
                        "fields": rule["oneOfRequired"],
                    }
                )

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
