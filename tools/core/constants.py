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
