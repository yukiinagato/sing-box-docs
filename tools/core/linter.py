"""Project-level config linter and normalizer for sing-box 1.14."""

from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from typing import Any

from tools.core.constants import NON_NATIVE_FIELD_PREFIXES, SHADOWSOCKS_2022_KEY_BYTES

ALLOWED_ROOT_KEYS = {
    "log",
    "dns",
    "ntp",
    "certificate",
    "certificate_providers",
    "endpoints",
    "inbounds",
    "outbounds",
    "route",
    "services",
    "experimental",
}

SHARED_OBJECT_ROOT_KEYS = {
    "tls",
    "transport",
    "v2ray_transport",
    "multiplex",
    "tcp_brutal",
    "udp_over_tcp",
}

TLS_SUB_FIELDS = {
    "disable_sni",
    "server_name",
    "insecure",
    "alpn",
    "min_version",
    "max_version",
    "cipher_suites",
    "certificate",
    "certificate_path",
    "key",
    "key_path",
    "ech",
    "ech_server_keys",
    "utls",
    "reality",
}

@dataclass
class LintResult:
    config: dict[str, Any]
    warnings: list[str]


class ProjectLinter:
    """Normalize and validate runtime config before persisting or testing."""

    def lint(self, config: dict[str, Any]) -> LintResult:
        normalized = copy.deepcopy(config)
        warnings: list[str] = []

        self._strip_non_native_fields(normalized, warnings)
        self._repair_root_scope_pollution(normalized, warnings)
        self._repair_shared_child_scopes(normalized, warnings)
        self._normalize_dns_route_shapes(normalized, warnings)
        self._validate_shadowsocks_keys(normalized)

        return LintResult(config=normalized, warnings=warnings)

    def _strip_non_native_fields(self, node: Any, warnings: list[str], path: str = "$") -> None:
        if isinstance(node, dict):
            for key in list(node.keys()):
                if any(key.startswith(prefix) for prefix in NON_NATIVE_FIELD_PREFIXES):
                    node.pop(key)
                    warnings.append(f"removed non-native field at {path}.{key}")
                    continue
                self._strip_non_native_fields(node[key], warnings, f"{path}.{key}")
            return
        if isinstance(node, list):
            for idx, item in enumerate(node):
                self._strip_non_native_fields(item, warnings, f"{path}[{idx}]")

    def _repair_root_scope_pollution(self, config: dict[str, Any], warnings: list[str]) -> None:
        inbounds = config.get("inbounds") if isinstance(config.get("inbounds"), list) else []
        outbounds = config.get("outbounds") if isinstance(config.get("outbounds"), list) else []

        for key in list(config.keys()):
            if key in ALLOWED_ROOT_KEYS:
                continue

            value = config.get(key)
            if key in SHARED_OBJECT_ROOT_KEYS:
                target_type = self._pick_target_type_for_shared_key(key, value, inbounds, outbounds)
                target_node = self._pick_target_node(target_type, inbounds, outbounds)
                if target_node is not None:
                    normalized_key = "transport" if key in {"transport", "v2ray_transport"} else key
                    target_node[normalized_key] = value
                    warnings.append(
                        f"moved illegal root field '{key}' into {target_type}[0].{normalized_key}"
                    )
                    config.pop(key, None)
                    continue

            warnings.append(f"illegal root field '{key}' detected at $.{key}; removed")
            config.pop(key, None)

    def _repair_shared_child_scopes(self, config: dict[str, Any], warnings: list[str]) -> None:
        for idx, node in enumerate(config.get("inbounds", [])):
            if isinstance(node, dict):
                self._merge_misplaced_tls_fields(node, f"$.inbounds[{idx}]", warnings)
        for idx, node in enumerate(config.get("outbounds", [])):
            if isinstance(node, dict):
                self._merge_misplaced_tls_fields(node, f"$.outbounds[{idx}]", warnings)

    def _merge_misplaced_tls_fields(self, node: dict[str, Any], path: str, warnings: list[str]) -> None:
        moved: dict[str, Any] = {}
        for key in list(node.keys()):
            if key in TLS_SUB_FIELDS:
                moved[key] = node.pop(key)
        if moved:
            tls = node.get("tls")
            if not isinstance(tls, dict):
                tls = {"enabled": True} if moved else {}
                node["tls"] = tls
            tls.update(moved)
            warnings.append(f"moved misplaced TLS fields under {path}.tls")

    def _pick_target_type_for_shared_key(
        self,
        key: str,
        value: Any,
        inbounds: list[Any],
        outbounds: list[Any],
    ) -> str:
        if key == "multiplex":
            return "outbound" if outbounds else "inbound"
        if key == "udp_over_tcp":
            return "inbound" if inbounds else "outbound"
        if isinstance(value, dict):
            if any(k in value for k in {"listen", "listen_port", "users", "sniff"}):
                return "inbound" if inbounds else "outbound"
            if any(k in value for k in {"server", "server_port", "uuid", "password"}):
                return "outbound" if outbounds else "inbound"
        return "outbound" if outbounds else "inbound"

    def _pick_target_node(self, target_type: str, inbounds: list[Any], outbounds: list[Any]) -> dict[str, Any] | None:
        if target_type == "inbound":
            return inbounds[0] if inbounds and isinstance(inbounds[0], dict) else None
        return outbounds[0] if outbounds and isinstance(outbounds[0], dict) else None

    def _normalize_dns_route_shapes(self, config: dict[str, Any], warnings: list[str]) -> None:
        dns = config.get("dns")
        if isinstance(dns, list):
            config["dns"] = {"servers": dns, "rules": []}
            warnings.append("dns was array; normalized to object with servers/rules")
        elif isinstance(dns, dict):
            if isinstance(dns.get("servers"), dict):
                dns["servers"] = [dns["servers"]]
                warnings.append("dns.servers was object; normalized to array")
            dns.setdefault("servers", [])
            dns.setdefault("rules", [])

        route = config.get("route")
        if isinstance(route, list):
            config["route"] = {"rules": route}
            warnings.append("route was array; normalized to object with rules")
        elif isinstance(route, dict):
            if isinstance(route.get("rules"), dict):
                route["rules"] = [route["rules"]]
                warnings.append("route.rules was object; normalized to array")
            route.setdefault("rules", [])

    def _validate_shadowsocks_keys(self, config: dict[str, Any]) -> None:
        for node in config.get("inbounds", []):
            self._validate_one_shadowsocks_node(node, "inbound")
        for node in config.get("outbounds", []):
            self._validate_one_shadowsocks_node(node, "outbound")

    def _validate_one_shadowsocks_node(self, node: Any, node_type: str) -> None:
        if not isinstance(node, dict) or node.get("type") != "shadowsocks":
            return
        method = node.get("method")
        if method not in SHADOWSOCKS_2022_KEY_BYTES:
            return

        password = node.get("password")
        if not isinstance(password, str):
            raise ValueError(f"{node_type} shadowsocks password must be string for {method}")

        expected = SHADOWSOCKS_2022_KEY_BYTES[method]
        try:
            decoded = base64.b64decode(password + "===", validate=True)
        except Exception as exc:  # pragma: no cover - explicit message path tested via ValueError
            raise ValueError(
                f"{node_type} shadowsocks password for {method} must be base64 with {expected} decoded bytes"
            ) from exc
        if len(decoded) != expected:
            raise ValueError(
                f"{node_type} shadowsocks password for {method} decoded length must be {expected}, got {len(decoded)}"
            )
