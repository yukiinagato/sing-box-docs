"""Core constants for sing-box 1.14 configuration generation."""

from __future__ import annotations

DEFAULT_SHADOWSOCKS_METHOD = "aes-128-gcm"

# Keys that should never be persisted to final sing-box runtime config.
NON_NATIVE_FIELD_PREFIXES = ("__",)

# 2022 methods require a base64-encoded key with strict decoded size.
SHADOWSOCKS_2022_KEY_BYTES = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
}

RECOMMENDED_BASE_CONFIG = {
    "log": {"level": "info", "timestamp": True},
    "dns": {"servers": [{"type": "local", "tag": "local-dns"}], "rules": []},
    "route": {"rules": []},
}

UI_SECURE_DEFAULTS = {
    "udp_over_tcp": True,
}

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

ROOT_SHARED_KEYS = ("tls", "transport", "v2ray_transport", "multiplex", "multipath", "mux")

# Semantic field calibration for builders/importers.
STRING_FIELD_KEYS = {
    "uuid",
    "server",
    "server_name",
    "public_key",
    "private_key",
    "short_id",
    "password",
}

NUMBER_FIELD_KEYS = {
    "server_port",
    "listen_port",
    "udp_timeout",
}

ARRAY_STRING_FIELD_KEYS = {
    "ip_cidr",
    "source_ip_cidr",
    "destination_ip_cidr",
}

# UI schema hints: fields that should be rendered as enum select widgets.
# Keep this list aligned with sing-box docs and tests' expected_config values.
ENUM_FIELD_OPTIONS = {
    "method": [
        "none",
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
    ],
    "protocol": ["dns", "http", "tls", "quic", "stun", "bittorrent"],
    "level": ["trace", "debug", "info", "warn", "error", "fatal", "panic"],
}
