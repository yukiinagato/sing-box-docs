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
