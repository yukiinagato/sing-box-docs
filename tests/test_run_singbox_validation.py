import os
from pathlib import Path

import pytest

from tools import run_singbox_validation as validator


def test_discover_binary_with_env(tmp_path, monkeypatch):
    fake = tmp_path / "sb"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("SING_BOX_BIN", str(fake))
    assert validator.discover_binary(tmp_path) == fake


def test_extract_error_field_and_suggestion():
    err = "error at $.route.rules[0].outbound: unknown field outbound_tag"
    assert validator.extract_error_field(err) == "$.route.rules[0].outbound"
    assert "重命名" in validator.suggest_schema_fix(err)


def test_validate_rule_files_invalid_json(tmp_path):
    (tmp_path / "ok.json").write_text('{"a":1}', encoding="utf-8")
    (tmp_path / "bad.json").write_text('{"a":', encoding="utf-8")
    errors = validator.validate_rule_files(tmp_path)
    assert len(errors) == 1
    assert "bad.json" in errors[0]


def test_run_validation_failure(monkeypatch, tmp_path):
    def fake_run(_):
        class R:
            returncode = 1
            stderr = "unknown field at $.dns.servers[0].address"

        return R()

    monkeypatch.setattr(validator, "run_cmd", fake_run)
    ok, message = validator.run_validation(tmp_path / "sb", tmp_path / "c.json", tmp_path)
    assert not ok
    assert "$.dns.servers[0].address" in message


@pytest.mark.integration
def test_run_validation_with_real_binary(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    binary = validator.discover_binary(repo_root)
    os.chmod(binary, os.stat(binary).st_mode | 0o100)

    config = tmp_path / "config.json"
    config_directory = tmp_path / "config_directory"
    config_directory.mkdir()

    config.write_text(
        """
        {
          "log": {"level": "info"},
          "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}
          ],
          "outbounds": [
            {"type": "direct", "tag": "direct"}
          ]
        }
        """,
        encoding="utf-8",
    )

    ok, message = validator.run_validation(binary, config, config_directory)
    assert ok, message
