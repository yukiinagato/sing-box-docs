import pytest

from tools.config_generation import validate_config


def base_config():
    return {
        "log": {"level": "info"},
        "dns": {
            "servers": [{"type": "udp", "address": "1.1.1.1"}],
            "rules": [{"domain_suffix": ["example.com"], "server": "dns-remote"}],
        },
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen_port": 1080}],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {
                "type": "shadowsocks",
                "tag": "ss-out",
                "server": "1.2.3.4",
                "server_port": 443,
            },
        ],
        "route": {
            "rules": [
                {"domain": ["api.example.com"], "outbound": "ss-out"},
                {"ip_cidr": ["10.0.0.0/8"], "outbound": "direct"},
                {"geoip": ["cn"], "outbound": "direct"},
            ]
        },
    }


@pytest.mark.parametrize("inbound_type", ["socks", "http", "mixed", "tun"])
def test_validate_config_inbound_matrix(inbound_type):
    config = base_config()
    config["inbounds"][0]["type"] = inbound_type
    validate_config(config)


@pytest.mark.parametrize("outbound_type", ["direct", "block", "dns"])
def test_validate_config_simple_outbound_types(outbound_type):
    config = base_config()
    config["outbounds"] = [{"type": outbound_type, "tag": outbound_type}]
    config["route"]["rules"] = [{"domain_suffix": ["example.org"], "outbound": outbound_type}]
    validate_config(config)


def test_validate_config_with_trojan_outbound():
    config = base_config()
    config["outbounds"][1] = {
        "type": "trojan",
        "tag": "trojan-out",
        "server": "trojan.example.com",
        "server_port": 443,
    }
    config["route"]["rules"][0]["outbound"] = "trojan-out"
    validate_config(config)


def test_invalid_port_type_rejected():
    config = base_config()
    config["inbounds"][0]["listen_port"] = "1080"
    with pytest.raises(ValueError, match="must be an integer"):
        validate_config(config)


def test_invalid_route_reference_rejected():
    config = base_config()
    config["route"]["rules"][0]["outbound"] = "missing-tag"
    with pytest.raises(ValueError, match="unknown tag"):
        validate_config(config)


def test_dns_rule_requires_matcher():
    config = base_config()
    config["dns"]["rules"] = [{"server": "dns-remote"}]
    with pytest.raises(ValueError, match="must contain"):
        validate_config(config)


def test_missing_top_level_field_rejected():
    config = base_config()
    config.pop("route")
    with pytest.raises(ValueError, match="missing top-level field"):
        validate_config(config)
