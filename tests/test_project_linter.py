import pytest
import json

from tools.core.linter import ProjectLinter


def test_linter_normalizes_dns_and_route_arrays():
    config = {
        "dns": [{"type": "local", "tag": "local"}],
        "route": [{"ip_cidr": ["10.0.0.0/8"], "outbound": "direct"}],
        "inbounds": [],
        "outbounds": [],
    }
    result = ProjectLinter().lint(config)
    assert isinstance(result.config["dns"], dict)
    assert isinstance(result.config["route"], dict)
    assert any("dns was array" in w for w in result.warnings)
    assert any("route was array" in w for w in result.warnings)


def test_linter_removes_non_native_fields():
    config = {
        "dns": {"servers": [], "rules": [], "__page_id": "dns"},
        "route": {"rules": []},
        "inbounds": [{"type": "mixed", "listen_port": 2080, "__meta": "x"}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    result = ProjectLinter().lint(config)
    assert "__page_id" not in result.config["dns"]
    assert "__meta" not in result.config["inbounds"][0]


def test_linter_moves_illegal_root_shared_fields_into_outbound():
    config = {
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen_port": 2080}],
        "outbounds": [{"type": "vmess", "tag": "proxy", "server": "example.com", "server_port": 443}],
        "tls": {"enabled": True, "server_name": "example.com"},
        "transport": {"type": "ws", "path": "/ws"},
        "route": {"rules": []},
    }
    result = ProjectLinter().lint(config)

    assert "tls" not in result.config
    assert "transport" not in result.config
    assert result.config["outbounds"][0]["tls"]["server_name"] == "example.com"
    assert result.config["outbounds"][0]["transport"]["path"] == "/ws"
    assert any("illegal root field" in warning or "moved illegal root field" in warning for warning in result.warnings)


def test_linter_rehomes_misplaced_tls_fields_inside_outbound_tls():
    config = {
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
    result = ProjectLinter().lint(config)
    outbound = result.config["outbounds"][0]

    assert "server_name" not in outbound
    assert "alpn" not in outbound
    assert outbound["tls"]["server_name"] == "example.com"
    assert outbound["tls"]["alpn"] == ["h2"]


def test_linter_rejects_invalid_2022_key_length():
    config = {
        "dns": {"servers": [], "rules": []},
        "route": {"rules": []},
        "inbounds": [],
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": "ss-out",
                "method": "2022-blake3-aes-128-gcm",
                "password": "abcd",
            }
        ],
    }
    with pytest.raises(ValueError, match="base64"):
        ProjectLinter().lint(config)


def test_linter_migrates_root_shared_fields_into_inbound_outbound():
    config = {
        "dns": {"servers": [], "rules": []},
        "route": {"rules": []},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen_port": 2080}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "tls": {"enabled": True, "insecure": False},
    }
    result = ProjectLinter().lint(config)
    assert "tls" not in result.config
    assert result.config["inbounds"][0]["tls"]["enabled"] is True
    assert result.config["outbounds"][0]["tls"]["enabled"] is True
    assert any("migrated root tls" in w for w in result.warnings)


def test_linter_enforces_root_whitelist():
    config = {
        "dns": {"servers": [], "rules": []},
        "route": {"rules": []},
        "inbounds": [],
        "outbounds": [],
        "foo": {"bar": 1},
    }
    result = ProjectLinter().lint(config)
    assert "foo" not in result.config
    assert any("illegal root field removed: foo" in w for w in result.warnings)


def test_linter_accepts_golden_style_uuid_cidr_and_actions():
    config = {
        "dns": {
            "servers": [{"tag": "dns_direct", "type": "https", "server": "1.1.1.1"}],
            "rules": [{"domain_suffix": [".lan"], "server": "dns_direct"}],
            "final": "dns_direct",
        },
        "inbounds": [{"type": "tproxy", "tag": "tproxy-in", "listen": "::", "listen_port": 12345}],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {
                "type": "vmess",
                "tag": "proxy",
                "server": "116.147.152.85",
                "server_port": 4551,
                "uuid": "2b776a49-4136-4b2b-9cf7-7d86be3198b0",
            },
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"source_ip_cidr": ["10.10.38.44/32"], "outbound": "proxy"},
            ]
        },
    }
    result = ProjectLinter().lint(config)
    assert result.config["outbounds"][1]["uuid"] == "2b776a49-4136-4b2b-9cf7-7d86be3198b0"
    assert result.config["route"]["rules"][0]["action"] == "sniff"
    assert result.config["route"]["rules"][1]["action"] == "hijack-dns"


def test_linter_wraps_scalar_array_fields_as_atomic_items():
    config = {
        "dns": {
            "servers": [{"tag": "dns-local", "type": "udp", "server": "127.0.0.1"}],
            "rules": [{"query_type": "AAAA", "server": "dns-local"}],
        },
        "route": {"rules": [{"ip_version": 4, "outbound": "direct"}]},
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "inbounds": [],
    }
    result = ProjectLinter().lint(config)
    assert result.config["dns"]["rules"][0]["query_type"] == ["AAAA"]
    assert result.config["route"]["rules"][0]["ip_version"] == [4]


def test_route_rule_schema_required_flags_are_polymorphic():
    with open("generated/configuration-schemas/route.json", "r", encoding="utf-8") as fh:
        schema = json.load(fh)
    rule_page = next(page for page in schema["pages"] if page["page_id"] == "rule")
    assert rule_page["fields"]["action"]["required"] is False
    assert rule_page["fields"]["mode"]["required"] is False
    assert rule_page["fields"]["rules"]["required"] is False
