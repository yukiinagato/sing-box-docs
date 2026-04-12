#!/usr/bin/env python3
"""Helpers for generating and validating sing-box configuration dictionaries."""

from __future__ import annotations

import copy
import warnings
from typing import Any

from tools.core.constants import DEFAULT_SHADOWSOCKS_METHOD, RECOMMENDED_BASE_CONFIG, ROOT_ALLOWED_KEYS
from tools.core.linter import ProjectLinter

SUPPORTED_INBOUND_TYPES = {"socks", "http", "mixed", "tun", "shadowsocks"}
SUPPORTED_OUTBOUND_TYPES = {"direct", "block", "dns", "shadowsocks", "trojan"}
ALLOWED_ROOT_KEYS = ROOT_ALLOWED_KEYS


def _ensure_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def _ensure_list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array")
    return value


def _ensure_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    return value


def _validate_port(value: Any, name: str) -> int:
    port = _ensure_int(value, name)
    if not 1 <= port <= 65535:
        raise ValueError(f"{name} must be in range 1-65535")
    return port


def validate_dns(dns: Any, outbound_tags: set[str]) -> set[str]:
    dns_obj = _ensure_dict(dns, "dns")
    servers = _ensure_list(dns_obj.get("servers", []), "dns.servers")
    dns_tags: set[str] = set()
    for idx, server in enumerate(servers):
        server_obj = _ensure_dict(server, f"dns.servers[{idx}]")
        if "type" in server_obj and not isinstance(server_obj["type"], str):
            raise ValueError(f"dns.servers[{idx}].type must be a string")
        if "address" in server_obj and not isinstance(server_obj["address"], str):
            raise ValueError(f"dns.servers[{idx}].address must be a string")
        if "server" in server_obj and not isinstance(server_obj["server"], str):
            raise ValueError(f"dns.servers[{idx}].server must be a string")
        if "server_port" in server_obj:
            _validate_port(server_obj["server_port"], f"dns.servers[{idx}].server_port")
        if "tag" in server_obj:
            if not isinstance(server_obj["tag"], str):
                raise ValueError(f"dns.servers[{idx}].tag must be a string")
            dns_tags.add(server_obj["tag"])
        detour = server_obj.get("detour")
        if detour is not None and (not isinstance(detour, str) or (outbound_tags and detour not in outbound_tags)):
            raise ValueError(f"dns.servers[{idx}].detour references unknown tag: {detour}")

    rules = _ensure_list(dns_obj.get("rules", []), "dns.rules")
    for idx, rule in enumerate(rules):
        rule_obj = _ensure_dict(rule, f"dns.rules[{idx}]")
        has_matcher = any(k in rule_obj for k in ("domain", "domain_suffix", "ip_cidr", "geoip"))
        if not has_matcher:
            raise ValueError(f"dns.rules[{idx}] must contain domain/domain_suffix/ip_cidr/geoip")
        server = rule_obj.get("server")
        if server is not None and (not isinstance(server, str) or (dns_tags and server not in dns_tags)):
            raise ValueError(f"dns.rules[{idx}].server references unknown tag: {server}")
    return dns_tags


def validate_inbounds(inbounds: Any) -> None:
    inb_list = _ensure_list(inbounds, "inbounds")
    if not inb_list:
        raise ValueError("inbounds cannot be empty")

    for idx, inbound in enumerate(inb_list):
        inb = _ensure_dict(inbound, f"inbounds[{idx}]")
        inbound_type = inb.get("type")
        if inbound_type not in SUPPORTED_INBOUND_TYPES:
            raise ValueError(f"inbounds[{idx}].type unsupported: {inbound_type}")
        _validate_port(inb.get("listen_port"), f"inbounds[{idx}].listen_port")
        if "tag" in inb and not isinstance(inb["tag"], str):
            raise ValueError(f"inbounds[{idx}].tag must be a string")


def validate_outbounds(outbounds: Any) -> None:
    ob_list = _ensure_list(outbounds, "outbounds")
    if not ob_list:
        raise ValueError("outbounds cannot be empty")

    for idx, outbound in enumerate(ob_list):
        ob = _ensure_dict(outbound, f"outbounds[{idx}]")
        outbound_type = ob.get("type")
        if outbound_type not in SUPPORTED_OUTBOUND_TYPES:
            raise ValueError(f"outbounds[{idx}].type unsupported: {outbound_type}")
        if "tag" not in ob or not isinstance(ob["tag"], str):
            raise ValueError(f"outbounds[{idx}].tag is required and must be a string")

        if outbound_type in {"shadowsocks", "trojan"}:
            if not isinstance(ob.get("server"), str):
                raise ValueError(f"outbounds[{idx}].server must be a string")
            _validate_port(ob.get("server_port"), f"outbounds[{idx}].server_port")


def validate_route(route: Any, outbound_tags: set[str]) -> None:
    route_obj = _ensure_dict(route, "route")
    rules = _ensure_list(route_obj.get("rules", []), "route.rules")
    for idx, rule in enumerate(rules):
        rule_obj = _ensure_dict(rule, f"route.rules[{idx}]")
        has_matcher = any(k in rule_obj for k in ("domain", "domain_suffix", "ip_cidr", "geoip"))
        if not has_matcher:
            raise ValueError(f"route.rules[{idx}] must include domain/ip/geop matcher")
        out = rule_obj.get("outbound")
        if not isinstance(out, str):
            raise ValueError(f"route.rules[{idx}].outbound must be a string")
        if out not in outbound_tags:
            raise ValueError(f"route.rules[{idx}].outbound references unknown tag: {out}")
        action = rule_obj.get("action")
        if action is not None and not isinstance(action, str):
            raise ValueError(f"route.rules[{idx}].action must be a string")


def validate_config(config: Any) -> None:
    cfg = _ensure_dict(config, "config")

    unknown_roots = [key for key in cfg if key not in ALLOWED_ROOT_KEYS]
    if unknown_roots:
        raise ValueError(
            f"illegal root field(s): {', '.join(sorted(unknown_roots))}; "
            f"allowed: {', '.join(sorted(ALLOWED_ROOT_KEYS))}"
        )

    for top in ("log", "dns", "inbounds", "outbounds", "route"):
        if top not in cfg:
            raise ValueError(f"missing top-level field: {top}")

    _ensure_dict(cfg["log"], "log")
    validate_inbounds(cfg["inbounds"])
    validate_outbounds(cfg["outbounds"])
    outbound_tags = {ob["tag"] for ob in cfg["outbounds"] if isinstance(ob, dict) and isinstance(ob.get("tag"), str)}
    validate_dns(cfg["dns"], outbound_tags)
    validate_route(cfg["route"], outbound_tags)


def _prune_defaults(value: Any, default: Any) -> Any:
    if isinstance(value, dict) and isinstance(default, dict):
        pruned: dict[str, Any] = {}
        for key, current in value.items():
            if key not in default:
                pruned[key] = current
                continue
            candidate = _prune_defaults(current, default[key])
            if candidate != default[key]:
                pruned[key] = candidate
        return pruned
    if isinstance(value, list):
        return [_prune_defaults(item, None) for item in value]
    return value


def remove_default_fields(config: dict[str, Any]) -> dict[str, Any]:
    return _prune_defaults(copy.deepcopy(config), RECOMMENDED_BASE_CONFIG)


def normalize_and_lint_config(config: dict[str, Any]) -> dict[str, Any]:
    lint_result = ProjectLinter().lint(config, strict_root=True)
    for item in lint_result.warnings:
        warnings.warn(item, RuntimeWarning, stacklevel=2)
    return lint_result.config


def generate_tunnel_pair(
    *,
    server_port: int,
    client_port: int,
    password: str,
    method: str = DEFAULT_SHADOWSOCKS_METHOD,
    server_host: str = "127.0.0.1",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Generate a working server/client config pair for local E2E proxy testing."""
    _validate_port(server_port, "server_port")
    _validate_port(client_port, "client_port")
    if not isinstance(password, str) or not password.strip():
        raise ValueError("password must be a non-empty string")
    if not isinstance(method, str) or not method.strip():
        raise ValueError("method must be a non-empty string")
    if not isinstance(server_host, str) or not server_host.strip():
        raise ValueError("server_host must be a non-empty string")

    server = {
        "log": dict(RECOMMENDED_BASE_CONFIG["log"]),
        "dns": {"servers": [{"type": "local", "tag": "local-dns"}], "rules": []},
        "inbounds": [
            {
                "type": "shadowsocks",
                "tag": "ss-in",
                "listen": "127.0.0.1",
                "listen_port": server_port,
                "method": method,
                "password": password,
            }
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct", "rules": []},
    }

    client = {
        "log": dict(RECOMMENDED_BASE_CONFIG["log"]),
        "dns": {
            "servers": [{"type": "local", "tag": "local-dns", "detour": "direct"}],
            "rules": [],
            "final": "local-dns",
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": client_port,
            }
        ],
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": "ss-out",
                "server": server_host,
                "server_port": server_port,
                "method": method,
                "password": password,
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "rules": [{"ip_cidr": ["127.0.0.0/8"], "outbound": "ss-out"}],
            "final": "ss-out",
        },
    }

    return normalize_and_lint_config(server), normalize_and_lint_config(client)
