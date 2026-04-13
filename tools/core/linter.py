"""Project-level config linter and normalizer for sing-box 1.14."""

from __future__ import annotations

import base64
import copy
import ipaddress
from dataclasses import dataclass
from typing import Any

from tools.core.constants import (
    ARRAY_CIDR_FIELD_KEYS,
    ARRAY_INTEGER_FIELD_KEYS,
    ARRAY_STRING_FIELD_KEYS,
    NON_NATIVE_FIELD_PREFIXES,
    NUMBER_FIELD_KEYS,
    ROOT_ALLOWED_KEYS,
    ROOT_SHARED_KEYS,
    SHADOWSOCKS_2022_KEY_BYTES,
    STRING_FIELD_KEYS,
)

ALLOWED_ROOT_KEYS = ROOT_ALLOWED_KEYS
SHARED_OBJECT_ROOT_KEYS = set(ROOT_SHARED_KEYS) | {"tcp_brutal", "udp_over_tcp"}

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

    ROOT_ALLOWED_KEYS = ROOT_ALLOWED_KEYS
    ROOT_SHARED_KEYS = ROOT_SHARED_KEYS
    ROOT_REHOME_GUIDE = {
        "tls": "$.inbounds[i].tls / $.outbounds[i].tls / $.endpoints[i].tls",
        "transport": "$.inbounds[i].transport / $.outbounds[i].transport / $.endpoints[i].transport",
        "v2ray_transport": "$.inbounds[i].transport / $.outbounds[i].transport / $.endpoints[i].transport",
        "multiplex": "$.inbounds[i].multiplex / $.outbounds[i].multiplex / $.endpoints[i].multiplex",
        "mux": "$.inbounds[i].multiplex / $.outbounds[i].multiplex / $.endpoints[i].multiplex",
        "multipath": "$.inbounds[i].multipath / $.outbounds[i].multipath / $.endpoints[i].multipath",
    }

    def lint(self, config: dict[str, Any], *, strict_root: bool = False) -> LintResult:
        normalized = copy.deepcopy(config)
        warnings: list[str] = []

        self._calibrate_semantic_types(normalized, warnings)
        self._strip_non_native_fields(normalized, warnings)
        self._repair_root_scope_pollution(normalized, warnings)
        self._repair_shared_child_scopes(normalized, warnings)
        self._normalize_dns_route_shapes(normalized, warnings)
        self._migrate_root_shared_fields(normalized, warnings)
        self._migrate_dns_server_legacy_address(normalized, warnings)
        self._normalize_route_rule_actions(normalized, warnings)
        self._enforce_root_whitelist(normalized, warnings, strict_root=strict_root)
        self._validate_tag_references(normalized)
        self._validate_endpoint_integrity(normalized)
        self._detect_detour_cycles(normalized)
        self._validate_shared_field_scopes(normalized, warnings)
        self._validate_shadowsocks_keys(normalized)
        self._validate_ip_cidr_fields(normalized)

        return LintResult(config=normalized, warnings=warnings)

    def _calibrate_semantic_types(self, node: Any, warnings: list[str], path: str = "$") -> Any:
        if isinstance(node, dict):
            for key in list(node.keys()):
                value = node[key]
                next_path = f"{path}.{key}"
                if key in STRING_FIELD_KEYS and isinstance(value, (int, float, bool)):
                    node[key] = str(value)
                    warnings.append(f"coerced {next_path} to string")
                    value = node[key]
                elif key in NUMBER_FIELD_KEYS and isinstance(value, str) and value.strip().isdigit():
                    node[key] = int(value)
                    warnings.append(f"coerced {next_path} to integer")
                    value = node[key]
                elif key == "query_type":
                    if isinstance(value, list):
                        normalized: list[Any] = []
                        changed = False
                        for item in value:
                            if isinstance(item, bool):
                                normalized.append(str(item))
                                changed = True
                            elif isinstance(item, float) and item.is_integer():
                                normalized.append(int(item))
                                changed = True
                            elif isinstance(item, (int, str)):
                                normalized.append(item)
                            else:
                                normalized.append(str(item))
                                changed = True
                        if changed:
                            node[key] = normalized
                            warnings.append(f"normalized {next_path} as mixed query_type array")
                            value = node[key]
                    elif isinstance(value, (str, int)):
                        node[key] = [value]
                        warnings.append(f"wrapped {next_path} scalar into query_type array")
                        value = node[key]
                elif key in (ARRAY_STRING_FIELD_KEYS | ARRAY_CIDR_FIELD_KEYS) and isinstance(value, list):
                    casted = [str(item) for item in value]
                    if casted != value:
                        node[key] = casted
                        warnings.append(f"coerced {next_path} list entries to string")
                        value = node[key]
                elif key in (ARRAY_STRING_FIELD_KEYS | ARRAY_CIDR_FIELD_KEYS) and isinstance(value, (str, int, float, bool)):
                    node[key] = [str(value)]
                    warnings.append(f"wrapped {next_path} scalar into string array")
                    value = node[key]
                elif key in ARRAY_INTEGER_FIELD_KEYS and isinstance(value, list):
                    casted_int = [int(item) for item in value if isinstance(item, (int, float, str)) and str(item).strip().isdigit()]
                    if casted_int and casted_int != value:
                        node[key] = casted_int
                        warnings.append(f"coerced {next_path} list entries to integer")
                        value = node[key]
                elif key in ARRAY_INTEGER_FIELD_KEYS and isinstance(value, (int, float, str)) and str(value).strip().isdigit():
                    node[key] = [int(value)]
                    warnings.append(f"wrapped {next_path} scalar into integer array")
                    value = node[key]
                self._calibrate_semantic_types(value, warnings, next_path)
            return node
        if isinstance(node, list):
            for idx, item in enumerate(node):
                self._calibrate_semantic_types(item, warnings, f"{path}[{idx}]")
        return node

    def _validate_ip_cidr_fields(self, node: Any, path: str = "$") -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                next_path = f"{path}.{key}"
                if key in ARRAY_CIDR_FIELD_KEYS and isinstance(value, list):
                    for idx, cidr in enumerate(value):
                        if not isinstance(cidr, str):
                            raise ValueError(f"{next_path}[{idx}] must be string CIDR")
                        try:
                            ipaddress.ip_network(cidr, strict=False)
                        except ValueError as exc:
                            raise ValueError(f"{next_path}[{idx}] invalid CIDR: {cidr}") from exc
                if key == "ip_version":
                    if value not in (None, 4, 6):
                        raise ValueError(f"{next_path} invalid ip_version: {value}")
                if key == "udp_timeout" and value is not None and not isinstance(value, str):
                    raise ValueError(f"{next_path} must be duration string")
                if key == "query_type":
                    if isinstance(value, list):
                        for idx, item in enumerate(value):
                            if not isinstance(item, (str, int)) or isinstance(item, bool):
                                raise ValueError(f"{next_path}[{idx}] must be string or integer")
                    elif value is not None and not isinstance(value, (str, int)):
                        raise ValueError(f"{next_path} must be string, integer, or array")
                self._validate_ip_cidr_fields(value, next_path)
            return
        if isinstance(node, list):
            for idx, item in enumerate(node):
                self._validate_ip_cidr_fields(item, f"{path}[{idx}]")

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
        for key in list(config.keys()):
            if key in ALLOWED_ROOT_KEYS:
                continue

            if key in SHARED_OBJECT_ROOT_KEYS:
                # Shared fields are migrated in _migrate_root_shared_fields.
                continue

            warnings.append(f"illegal root field '{key}' detected at $.{key}; scheduled for removal")

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

    def _migrate_dns_server_legacy_address(self, config: dict[str, Any], warnings: list[str]) -> None:
        dns = config.get("dns")
        if not isinstance(dns, dict):
            return
        servers = dns.get("servers")
        if not isinstance(servers, list):
            return
        for idx, server in enumerate(servers):
            if not isinstance(server, dict):
                continue
            address = server.get("address")
            if not isinstance(address, str) or server.get("type"):
                continue
            migrated = dict(server)
            host = address
            port = 53
            if ":" in address and not address.startswith("["):
                maybe_host, maybe_port = address.rsplit(":", 1)
                if maybe_port.isdigit():
                    host = maybe_host
                    port = int(maybe_port)
            migrated["type"] = "udp"
            migrated["server"] = host
            migrated["server_port"] = port
            migrated.pop("address", None)
            servers[idx] = migrated
            warnings.append(f"migrated dns.servers[{idx}].address to 1.14 structured server/server_port fields")

    def _normalize_route_rule_actions(self, config: dict[str, Any], warnings: list[str]) -> None:
        route = config.get("route")
        rules = route.get("rules") if isinstance(route, dict) else None
        if not isinstance(rules, list):
            return
        for idx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            if "outbound" in rule and "action" not in rule:
                rule["action"] = "route"
                warnings.append(f"route.rules[{idx}] missing action; normalized to action=route for outbound dispatch")

    def _validate_shadowsocks_keys(self, config: dict[str, Any]) -> None:
        for node in config.get("inbounds", []):
            self._validate_one_shadowsocks_node(node, "inbound")
        for node in config.get("outbounds", []):
            self._validate_one_shadowsocks_node(node, "outbound")

    def _migrate_root_shared_fields(self, config: dict[str, Any], warnings: list[str]) -> None:
        for key in self.ROOT_SHARED_KEYS:
            if key not in config:
                continue
            config.pop(key)
            normalized_key = "transport" if key == "v2ray_transport" else ("multiplex" if key == "mux" else key)
            warnings.append(
                f"removed illegal root shared field '{key}'; place it only under compatible inbound/outbound/endpoint nodes"
            )
            warnings.append(f"dropped root {normalized_key} to avoid invalid runtime fields")

    def _enforce_root_whitelist(
        self,
        config: dict[str, Any],
        warnings: list[str],
        *,
        strict_root: bool = False,
    ) -> None:
        illegal_root_keys: list[str] = []
        for key in list(config.keys()):
            if key in self.ROOT_ALLOWED_KEYS:
                continue
            illegal_root_keys.append(key)
            config.pop(key)
            warnings.append(
                f"illegal root field removed: {key} (allowed: {', '.join(sorted(self.ROOT_ALLOWED_KEYS))})"
            )
        if strict_root and illegal_root_keys:
            guide_lines = [
                f"illegal root field detected: {key}. move it under matching inbound/outbound/endpoint object."
                for key in illegal_root_keys
            ]
            for key in illegal_root_keys:
                if key in self.ROOT_REHOME_GUIDE:
                    guide_lines.append(f"{key} rehome path: {self.ROOT_REHOME_GUIDE[key]}")
            raise ValueError("\n".join(guide_lines))

    def _validate_shared_field_scopes(self, config: dict[str, Any], warnings: list[str]) -> None:
        shared_keys = {"tls", "transport", "multiplex", "multipath"}
        for section in ("inbounds", "outbounds", "endpoints"):
            nodes = config.get(section)
            if not isinstance(nodes, list):
                continue
            for idx, node in enumerate(nodes):
                if not isinstance(node, dict):
                    continue
                self._warn_shared_scope_in_nested(node, shared_keys, warnings, f"$.{section}[{idx}]", is_owner=True)

    def _warn_shared_scope_in_nested(
        self,
        node: Any,
        shared_keys: set[str],
        warnings: list[str],
        path: str,
        *,
        is_owner: bool = False,
    ) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in {"mux", "v2ray_transport"}:
                    warnings.append(f"legacy shared key {path}.{key} detected; use multiplex/transport")
                    continue
                if key in shared_keys and not is_owner:
                    raise ValueError(
                        f"shared field '{key}' is at wrong level: {path}.{key}; "
                        "expected under $.inbounds[i]/$.outbounds[i]/$.endpoints[i]"
                    )
                self._warn_shared_scope_in_nested(value, shared_keys, warnings, f"{path}.{key}", is_owner=False)
            return
        if isinstance(node, list):
            for idx, item in enumerate(node):
                self._warn_shared_scope_in_nested(item, shared_keys, warnings, f"{path}[{idx}]", is_owner=False)

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

    def _validate_tag_references(self, config: dict[str, Any]) -> None:
        inbound_tags = {
            node.get("tag")
            for node in config.get("inbounds", [])
            if isinstance(node, dict) and isinstance(node.get("tag"), str)
        }
        outbound_tags = {
            node.get("tag")
            for node in config.get("outbounds", [])
            if isinstance(node, dict) and isinstance(node.get("tag"), str)
        }
        dns_tags = {
            node.get("tag")
            for node in config.get("dns", {}).get("servers", [])
            if isinstance(node, dict) and isinstance(node.get("tag"), str)
        }

        def _iter_detours(node: Any) -> list[str]:
            refs: list[str] = []
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "detour" and isinstance(value, str):
                        refs.append(value)
                    refs.extend(_iter_detours(value))
            elif isinstance(node, list):
                for item in node:
                    refs.extend(_iter_detours(item))
            return refs

        for ref in _iter_detours(config):
            if ref not in outbound_tags:
                raise ValueError(f"detour references unknown tag: {ref}")

        dns_rules = config.get("dns", {}).get("rules", [])
        if isinstance(dns_rules, list):
            for idx, rule in enumerate(dns_rules):
                if not isinstance(rule, dict):
                    continue
                server_tag = rule.get("server")
                if isinstance(server_tag, str) and server_tag not in dns_tags:
                    raise ValueError(f"dns.rules[{idx}].server references unknown tag: {server_tag}")

        route_rules = config.get("route", {}).get("rules", [])
        builtin_outbounds = {"direct", "block", "dns"}
        if isinstance(route_rules, list):
            for idx, rule in enumerate(route_rules):
                if not isinstance(rule, dict):
                    continue
                outbound = rule.get("outbound")
                if (
                    isinstance(outbound, str)
                    and outbound not in outbound_tags
                    and outbound not in builtin_outbounds
                    and outbound_tags
                ):
                    raise ValueError(f"route.rules[{idx}].outbound references unknown tag: {outbound}")

        for idx, endpoint in enumerate(config.get("endpoints", [])):
            if not isinstance(endpoint, dict):
                continue
            ep_detour = endpoint.get("detour")
            if isinstance(ep_detour, str) and ep_detour not in outbound_tags:
                raise ValueError(f"endpoints[{idx}].detour references unknown tag: {ep_detour}")

        for idx, inbound in enumerate(config.get("inbounds", [])):
            if not isinstance(inbound, dict):
                continue
            if inbound.get("type") == "tun":
                for include_key in ("include_interface", "exclude_interface"):
                    interfaces = inbound.get(include_key)
                    if not isinstance(interfaces, list):
                        continue
                    for ip_idx, raw in enumerate(interfaces):
                        if not isinstance(raw, str):
                            continue
                        try:
                            ipaddress.ip_address(raw)
                        except ValueError:
                            # These fields can also contain interface names.
                            continue

    def _validate_endpoint_integrity(self, config: dict[str, Any]) -> None:
        endpoints = config.get("endpoints", [])
        if not isinstance(endpoints, list) or not endpoints:
            return

        endpoint_tags = {
            endpoint.get("tag")
            for endpoint in endpoints
            if isinstance(endpoint, dict) and isinstance(endpoint.get("tag"), str)
        }
        if not endpoint_tags:
            raise ValueError("endpoints defined but no endpoint.tag found")

        referenced_tags: set[str] = set()
        for outbound in config.get("outbounds", []):
            if not isinstance(outbound, dict):
                continue
            self._collect_named_refs(outbound, {"endpoint", "endpoint_tag"}, referenced_tags)

        dangling = sorted(endpoint_tags - referenced_tags)
        if dangling:
            raise ValueError(f"endpoint tags are not referenced by any outbound: {', '.join(dangling)}")

        for idx, endpoint in enumerate(endpoints):
            if not isinstance(endpoint, dict):
                continue
            ep_type = endpoint.get("type")
            if ep_type == "wireguard":
                if not isinstance(endpoint.get("private_key"), str) or not endpoint["private_key"].strip():
                    raise ValueError(f"endpoints[{idx}].private_key is required for wireguard endpoint")
                address = endpoint.get("address")
                if not isinstance(address, list) or not address:
                    raise ValueError(f"endpoints[{idx}].address is required for wireguard endpoint")
                peers = endpoint.get("peers")
                if not isinstance(peers, list) or not peers:
                    raise ValueError(f"endpoints[{idx}].peers is required for wireguard endpoint")
                for peer_idx, peer in enumerate(peers):
                    if not isinstance(peer, dict):
                        raise ValueError(f"endpoints[{idx}].peers[{peer_idx}] must be object")
                    if not isinstance(peer.get("address"), str):
                        raise ValueError(f"endpoints[{idx}].peers[{peer_idx}].address is required")
                    if not isinstance(peer.get("public_key"), str):
                        raise ValueError(f"endpoints[{idx}].peers[{peer_idx}].public_key is required")

            if ep_type == "shadowsocks":
                required = ("server", "server_port", "method", "password")
                for field in required:
                    if field not in endpoint:
                        raise ValueError(f"endpoints[{idx}].{field} is required for shadowsocks endpoint")

    def _detect_detour_cycles(self, config: dict[str, Any]) -> None:
        nodes: set[str] = set()
        edges: dict[str, set[str]] = {}

        def add_node(name: str) -> None:
            nodes.add(name)
            edges.setdefault(name, set())

        for outbound in config.get("outbounds", []):
            if isinstance(outbound, dict) and isinstance(outbound.get("tag"), str):
                add_node(f"outbound:{outbound['tag']}")

        dns_servers = config.get("dns", {}).get("servers", [])
        if isinstance(dns_servers, list):
            for idx, server in enumerate(dns_servers):
                if not isinstance(server, dict):
                    continue
                tag = server.get("tag") if isinstance(server.get("tag"), str) else f"__dns_index_{idx}"
                add_node(f"dns:{tag}")

        for outbound in config.get("outbounds", []):
            if not isinstance(outbound, dict) or not isinstance(outbound.get("tag"), str):
                continue
            src = f"outbound:{outbound['tag']}"
            detour = outbound.get("detour")
            if isinstance(detour, str):
                edges[src].add(f"outbound:{detour}")

        if isinstance(dns_servers, list):
            for idx, server in enumerate(dns_servers):
                if not isinstance(server, dict):
                    continue
                tag = server.get("tag") if isinstance(server.get("tag"), str) else f"__dns_index_{idx}"
                src = f"dns:{tag}"
                detour = server.get("detour")
                if isinstance(detour, str):
                    edges[src].add(f"outbound:{detour}")

        visiting: set[str] = set()
        visited: set[str] = set()
        stack: list[str] = []

        def dfs(node: str) -> None:
            if node in visited:
                return
            if node in visiting:
                cycle_start = stack.index(node) if node in stack else 0
                cycle = stack[cycle_start:] + [node]
                raise ValueError(f"detour cycle detected: {' -> '.join(cycle)}")
            visiting.add(node)
            stack.append(node)
            for nxt in edges.get(node, set()):
                if nxt in nodes:
                    dfs(nxt)
            stack.pop()
            visiting.remove(node)
            visited.add(node)

        for node in list(nodes):
            dfs(node)

    def _collect_named_refs(self, node: Any, target_keys: set[str], out: set[str]) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in target_keys and isinstance(value, str):
                    out.add(value)
                self._collect_named_refs(value, target_keys, out)
            return
        if isinstance(node, list):
            for item in node:
                self._collect_named_refs(item, target_keys, out)
