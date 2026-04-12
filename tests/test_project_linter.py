import pytest

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
