"""Project-level config linter and normalizer for sing-box 1.14."""

from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from typing import Any

from tools.core.constants import NON_NATIVE_FIELD_PREFIXES, SHADOWSOCKS_2022_KEY_BYTES


@dataclass
class LintResult:
    config: dict[str, Any]
    warnings: list[str]


class ProjectLinter:
    """Normalize and validate runtime config before persisting or testing."""

    ROOT_ALLOWED_KEYS = {
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
    ROOT_SHARED_KEYS = ("tls", "transport", "multiplex", "multipath")

    def lint(self, config: dict[str, Any]) -> LintResult:
        normalized = copy.deepcopy(config)
        warnings: list[str] = []

        self._strip_non_native_fields(normalized, warnings)
        self._normalize_dns_route_shapes(normalized, warnings)
        self._migrate_root_shared_fields(normalized, warnings)
        self._enforce_root_whitelist(normalized, warnings)
        self._validate_shared_field_scopes(normalized, warnings)
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

    def _migrate_root_shared_fields(self, config: dict[str, Any], warnings: list[str]) -> None:
        for key in self.ROOT_SHARED_KEYS:
            if key not in config:
                continue
            value = config.pop(key)
            migrated = 0
            for section in ("inbounds", "outbounds"):
                nodes = config.get(section)
                if not isinstance(nodes, list):
                    continue
                for node in nodes:
                    if not isinstance(node, dict):
                        continue
                    if key in node:
                        continue
                    node[key] = copy.deepcopy(value)
                    migrated += 1
            if migrated > 0:
                warnings.append(f"migrated root {key} into {migrated} inbound/outbound node(s)")
            else:
                warnings.append(f"detected illegal root field {key}, but no inbound/outbound target found")
                config[key] = value

    def _enforce_root_whitelist(self, config: dict[str, Any], warnings: list[str]) -> None:
        for key in list(config.keys()):
            if key in self.ROOT_ALLOWED_KEYS:
                continue
            config.pop(key)
            warnings.append(
                f"illegal root field removed: {key} (allowed: {', '.join(sorted(self.ROOT_ALLOWED_KEYS))})"
            )

    def _validate_shared_field_scopes(self, config: dict[str, Any], warnings: list[str]) -> None:
        shared_keys = set(self.ROOT_SHARED_KEYS)
        for section in ("inbounds", "outbounds", "endpoints"):
            nodes = config.get(section)
            if not isinstance(nodes, list):
                continue
            for idx, node in enumerate(nodes):
                if not isinstance(node, dict):
                    continue
                self._warn_shared_scope_in_nested(node, shared_keys, warnings, f"$.{section}[{idx}]")

    def _warn_shared_scope_in_nested(
        self,
        node: Any,
        shared_keys: set[str],
        warnings: list[str],
        path: str,
    ) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in shared_keys and path.count(".") > 1:
                    warnings.append(f"shared field {key} should be under inbound/outbound/endpoint object, got {path}.{key}")
                self._warn_shared_scope_in_nested(value, shared_keys, warnings, f"{path}.{key}")
            return
        if isinstance(node, list):
            for idx, item in enumerate(node):
                self._warn_shared_scope_in_nested(item, shared_keys, warnings, f"{path}[{idx}]")

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
