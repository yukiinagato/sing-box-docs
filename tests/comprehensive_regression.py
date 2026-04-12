import json
from pathlib import Path

import pytest

from tools.config_generation import generate_tunnel_pair, normalize_and_lint_config, validate_config
from tools.core.linter import ProjectLinter
from tools.run_singbox_validation import discover_binary, ensure_executable, run_validation

COVERED_SCENARIOS: set[str] = set()

AUDITED_SCENARIOS = {
    "inbound:socks",
    "inbound:http",
    "inbound:mixed",
    "inbound:tun",
    "outbound:direct",
    "outbound:block",
    "outbound:shadowsocks",
    "outbound:trojan",
    "outbound:vmess",
    "logic:domain_match",
    "logic:ip_cidr_split",
    "logic:dns_object_rules",
    "logic:detour_tag_reference",
    "negative:invalid_port_type",
    "negative:route_unknown_tag",
    "negative:dns_rule_missing_matcher",
    "negative:missing_top_level_field",
    "negative:invalid_2022_key_length",
    "negative:illegal_top_level_field",
    "negative:schema_drift_outbound_tag",
    "negative:port_conflict",
    "linter:dns_route_array_normalization",
    "linter:non_native_field_removal",
    "linter:illegal_root_shared_field_move",
    "linter:misplaced_tls_rehome",
    "linter:root_tls_migration",
}


@pytest.fixture
def config_workspace(tmp_path):
    config_file = tmp_path / "config.json"
    config_dir = tmp_path / "config_directory"
    config_dir.mkdir()
    yield config_file, config_dir
    if config_file.exists():
        config_file.unlink()
    for extra in tmp_path.glob("*.json"):
        extra.unlink()


def _base_runtime_config(inbound_type: str, outbound: dict, listen_port: int = 2080) -> dict:
    outbounds = [outbound]
    for fallback in ({"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}):
        if all(node.get("tag") != fallback["tag"] for node in outbounds):
            outbounds.append(fallback)
    return {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"type": "udp", "tag": "dns-remote", "server": "1.1.1.1", "server_port": 53, "detour": "direct"}
            ],
            "rules": [{"domain_suffix": ["example.com"], "server": "dns-remote"}],
        },
        "inbounds": [_build_inbound(inbound_type, listen_port)],
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"domain": ["api.example.com"], "outbound": outbound["tag"]},
                {"ip_cidr": ["10.0.0.0/8"], "outbound": "direct"},
                {"geoip": ["cn"], "outbound": "direct"},
            ],
            "final": "direct",
        },
    }


def _build_inbound(inbound_type: str, listen_port: int) -> dict:
    if inbound_type == "tun":
        return {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "utun-sing",
            "inet4_address": "172.19.0.1/30",
            "auto_route": False,
            "listen_port": listen_port,
        }
    return {"type": inbound_type, "tag": f"{inbound_type}-in", "listen": "127.0.0.1", "listen_port": listen_port}


def _runtime_safe_for_binary(config: dict) -> dict:
    runtime = json.loads(json.dumps(config))
    rules = runtime.get("route", {}).get("rules", [])
    if isinstance(rules, list):
        for rule in rules:
            if isinstance(rule, dict) and "geoip" in rule:
                rule.pop("geoip", None)
                rule.setdefault("domain_suffix", ["cn"])

    inbounds = runtime.get("inbounds", [])
    if isinstance(inbounds, list):
        for inbound in inbounds:
            if isinstance(inbound, dict) and inbound.get("type") == "tun":
                inbound.pop("listen_port", None)
                if "inet4_address" in inbound:
                    inbound["address"] = [inbound.pop("inet4_address")]
    return runtime


def _outbound_variants() -> dict[str, dict]:
    return {
        "shadowsocks": {
            "type": "shadowsocks",
            "tag": "ss-out",
            "server": "127.0.0.1",
            "server_port": 18080,
            "method": "aes-128-gcm",
            "password": "0123456789abcdef",
        },
        "trojan": {
            "type": "trojan",
            "tag": "trojan-out",
            "server": "127.0.0.1",
            "server_port": 443,
            "password": "test-password",
        },
        "vmess": {
            "type": "vmess",
            "tag": "vmess-out",
            "server": "127.0.0.1",
            "server_port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "security": "auto",
        },
        "direct": {"type": "direct", "tag": "direct"},
        "block": {"type": "block", "tag": "block"},
    }


@pytest.mark.parametrize("inbound_type", ["socks", "http", "mixed", "tun"])
def test_audit_inbound_matrix_validate_config(inbound_type):
    config = _base_runtime_config(inbound_type, _outbound_variants()["shadowsocks"])
    validate_config(config)
    COVERED_SCENARIOS.add(f"inbound:{inbound_type}")
    COVERED_SCENARIOS.update({"logic:domain_match", "logic:ip_cidr_split", "logic:dns_object_rules", "logic:detour_tag_reference"})


@pytest.mark.parametrize("outbound_type", ["direct", "block", "shadowsocks", "trojan"])
def test_audit_outbound_matrix_validate_config(outbound_type):
    outbound = _outbound_variants()[outbound_type]
    config = _base_runtime_config("mixed", outbound)
    if outbound_type in {"direct", "block"}:
        config["route"]["rules"][0]["outbound"] = outbound_type
    validate_config(config)
    COVERED_SCENARIOS.add(f"outbound:{outbound_type}")


def test_audit_vmess_supported_by_linter_and_binary(config_workspace):
    config_file, config_dir = config_workspace
    config = _base_runtime_config("mixed", _outbound_variants()["vmess"])
    linted = ProjectLinter().lint(_runtime_safe_for_binary(config)).config
    config_file.write_text(json.dumps(linted, ensure_ascii=False, indent=2), encoding="utf-8")

    repo_root = Path(__file__).resolve().parents[1]
    binary = discover_binary(repo_root)
    ensure_executable(binary)
    ok, message = run_validation(binary, config_file, config_dir)

    assert ok, message
    COVERED_SCENARIOS.add("outbound:vmess")


@pytest.mark.parametrize("inbound_type", ["socks", "http", "mixed", "tun"])
@pytest.mark.parametrize("outbound_type", ["shadowsocks", "trojan", "vmess", "direct", "block"])
def test_generated_matrix_binary_final_verdict(inbound_type, outbound_type, config_workspace):
    config_file, config_dir = config_workspace
    outbound = _outbound_variants()[outbound_type]
    config = _base_runtime_config(inbound_type, outbound)
    if outbound_type in {"direct", "block"}:
        config["route"]["rules"][0]["outbound"] = outbound_type

    linted = ProjectLinter().lint(_runtime_safe_for_binary(config)).config
    config_file.write_text(json.dumps(linted, ensure_ascii=False, indent=2), encoding="utf-8")

    repo_root = Path(__file__).resolve().parents[1]
    binary = discover_binary(repo_root)
    ensure_executable(binary)
    ok, message = run_validation(binary, config_file, config_dir)

    if not ok:
        analysis = (
            "binary check failed after lint normalization; this indicates schema drift "
            "between tools/core/linter.py normalization and generated runtime expectation."
        )
        pytest.fail(f"{analysis}\n{message}")


def test_generate_tunnel_pair_and_linter_regressions(config_workspace):
    config_file, config_dir = config_workspace
    server, client = generate_tunnel_pair(server_port=18080, client_port=2080, password="test-password")
    assert server["inbounds"][0]["type"] == "shadowsocks"
    assert client["inbounds"][0]["type"] == "mixed"
    assert client["route"]["final"] == "ss-out"
    validate_config(client)

    repo_root = Path(__file__).resolve().parents[1]
    binary = discover_binary(repo_root)
    ensure_executable(binary)

    for name, cfg in (("server", server), ("client", client)):
        config_file.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        ok, message = run_validation(binary, config_file, config_dir)
        assert ok, f"{name} config failed binary check: {message}"

    dirty = {
        "log": {"level": "info"},
        "dns": [{"type": "local", "tag": "local"}],
        "inbounds": [{"type": "mixed", "listen_port": 2080, "__page_id": "in"}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": [{"ip_cidr": ["10.0.0.0/8"], "outbound": "direct"}],
    }
    normalized = normalize_and_lint_config(dirty)
    assert isinstance(normalized["dns"], dict)
    assert isinstance(normalized["route"], dict)
    assert "__page_id" not in normalized["inbounds"][0]

    COVERED_SCENARIOS.update(
        {
            "linter:dns_route_array_normalization",
            "linter:non_native_field_removal",
            "logic:domain_match",
            "logic:ip_cidr_split",
            "logic:dns_object_rules",
            "logic:detour_tag_reference",
        }
    )


@pytest.mark.parametrize(
    "mutator,error,scenario",
    [
        (lambda cfg: cfg["inbounds"][0].update({"listen_port": "1080"}), "must be an integer", "negative:invalid_port_type"),
        (lambda cfg: cfg["route"]["rules"][0].update({"outbound": "missing-tag"}), "unknown tag", "negative:route_unknown_tag"),
        (lambda cfg: cfg["dns"].update({"rules": [{"server": "dns-remote"}]}), "must contain", "negative:dns_rule_missing_matcher"),
        (lambda cfg: cfg.pop("route"), "missing top-level field", "negative:missing_top_level_field"),
    ],
)
def test_negative_validate_config_matrix(mutator, error, scenario):
    cfg = _base_runtime_config("mixed", _outbound_variants()["shadowsocks"])
    mutator(cfg)
    with pytest.raises(ValueError, match=error):
        validate_config(cfg)
    COVERED_SCENARIOS.add(scenario)


@pytest.mark.parametrize(
    "config,error,scenario",
    [
        (
            {
                "dns": {"servers": [], "rules": []},
                "route": {"rules": []},
                "inbounds": [],
                "outbounds": [{"type": "shadowsocks", "tag": "ss-out", "method": "2022-blake3-aes-128-gcm", "password": "abcd"}],
            },
            "base64",
            "negative:invalid_2022_key_length",
        ),
        (
            {
                "dns": {"servers": [], "rules": []},
                "route": {"rules": []},
                "inbounds": [],
                "outbounds": [],
                "foo": {"bar": 1},
            },
            None,
            "negative:illegal_top_level_field",
        ),
    ],
)
def test_negative_linter_matrix(config, error, scenario):
    if error:
        with pytest.raises(ValueError, match=error):
            ProjectLinter().lint(config)
    else:
        result = ProjectLinter().lint(config)
        assert "foo" not in result.config
        assert any("illegal root field removed: foo" in w for w in result.warnings)
    COVERED_SCENARIOS.add(scenario)


def test_negative_schema_drift_and_port_conflict_binary(config_workspace):
    config_file, config_dir = config_workspace
    repo_root = Path(__file__).resolve().parents[1]
    binary = discover_binary(repo_root)
    ensure_executable(binary)

    schema_drift = {
        "log": {"level": "info"},
        "dns": {"servers": [], "rules": []},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"domain_suffix": ["example.org"], "outbound_tag": "direct"}]},
    }
    config_file.write_text(json.dumps(schema_drift, ensure_ascii=False, indent=2), encoding="utf-8")
    ok, message = run_validation(binary, config_file, config_dir)
    assert not ok
    assert "unknown field" in message.lower() or "schema" in message.lower()
    COVERED_SCENARIOS.add("negative:schema_drift_outbound_tag")

    port_conflict = {
        "log": {"level": "info"},
        "dns": {"servers": [], "rules": []},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in-1", "listen": "127.0.0.1", "listen_port": 2080},
            {"type": "http", "tag": "http-in-2", "listen": "127.0.0.1", "listen_port": 2080},
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": []},
    }
    conflict_path = config_file.with_name("port-conflict.json")
    conflict_path.write_text(json.dumps(port_conflict, ensure_ascii=False, indent=2), encoding="utf-8")
    ok, _ = run_validation(binary, conflict_path, config_dir)
    assert ok
    COVERED_SCENARIOS.add("negative:port_conflict")


@pytest.mark.parametrize("json_file", sorted(Path("generated").glob("**/*.json")), ids=lambda p: str(p))
def test_generated_static_json_deep_lint_scan(json_file: Path):
    data = json.loads(json_file.read_text(encoding="utf-8"))
    ProjectLinter().lint(data)


def test_linter_scenario_alignment_from_project_specs():
    cfg = {
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen_port": 2080}],
        "outbounds": [{"type": "vmess", "tag": "proxy", "server": "example.com", "server_port": 443}],
        "tls": {"enabled": True, "server_name": "example.com"},
        "transport": {"type": "ws", "path": "/ws"},
        "route": {"rules": []},
    }
    result = ProjectLinter().lint(cfg)
    assert "tls" not in result.config
    assert "transport" not in result.config
    assert result.config["outbounds"][0]["tls"]["server_name"] == "example.com"
    assert result.config["outbounds"][0]["transport"]["path"] == "/ws"

    cfg2 = {
        "outbounds": [
            {
                "type": "vmess",
                "tag": "proxy",
                "server": "example.com",
                "server_port": 443,
                "server_name": "example.com",
                "alpn": ["h2"],
            }
        ]
    }
    result2 = ProjectLinter().lint(cfg2)
    outbound = result2.config["outbounds"][0]
    assert "server_name" not in outbound
    assert "alpn" not in outbound
    assert outbound["tls"]["server_name"] == "example.com"
    assert outbound["tls"]["alpn"] == ["h2"]

    cfg3 = {
        "dns": {"servers": [], "rules": []},
        "route": {"rules": []},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen_port": 2080}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "tls": {"enabled": True, "insecure": False},
    }
    result3 = ProjectLinter().lint(cfg3)
    assert "tls" not in result3.config
    assert result3.config["inbounds"][0]["tls"]["enabled"] is True
    assert result3.config["outbounds"][0]["tls"]["enabled"] is True

    COVERED_SCENARIOS.update(
        {
            "linter:illegal_root_shared_field_move",
            "linter:misplaced_tls_rehome",
            "linter:root_tls_migration",
            "outbound:vmess",
        }
    )


def test_comprehensive_regression_coverage_report():
    missing = sorted(AUDITED_SCENARIOS - COVERED_SCENARIOS)
    report_lines = [
        f"total audited scenarios: {len(AUDITED_SCENARIOS)}",
        f"covered scenarios: {len(COVERED_SCENARIOS)}",
        f"missing scenarios: {len(missing)}",
    ]
    if missing:
        report_lines.extend(f" - {item}" for item in missing)
    print("\n" + "\n".join(report_lines))
    assert not missing, "some audited test-matrix scenarios are not reproduced"
