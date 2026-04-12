#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from pathlib import Path


def discover_binary(repo_root: Path) -> Path:
    env_bin = os.environ.get("SING_BOX_BIN")
    if env_bin:
        return (repo_root / env_bin).resolve() if not os.path.isabs(env_bin) else Path(env_bin)

    candidates = sorted((repo_root / "tools").glob("sing-box-*/sing-box"))
    if not candidates:
        raise FileNotFoundError("Cannot find sing-box binary under tools/sing-box-*/sing-box")
    return candidates[-1]


def ensure_executable(binary_path: Path) -> None:
    mode = binary_path.stat().st_mode
    if not (mode & stat.S_IXUSR):
        binary_path.chmod(mode | stat.S_IXUSR)


def run_cmd(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True)


def suggest_schema_fix(stderr: str) -> str:
    lowered = stderr.lower()
    if "unknown field" in lowered:
        return "检测到 unknown field：请对照 sing-box 1.14 文档检查字段是否重命名，或字段位置是否迁移。"
    if "cannot unmarshal" in lowered or "invalid character" in lowered:
        return "检测到 JSON 类型/格式错误：请检查字段类型（如 port 应为整数，数组字段应为数组）。"
    if "not found" in lowered and "rule" in lowered:
        return "检测到规则集文件路径问题：请确认 config_directory 下文件名与 rule_set 引用一致。"
    return "请根据错误路径定位字段，并与 1.14.0 schema 对照调整。"


def extract_error_field(stderr: str) -> str | None:
    patterns = [
        r"\$\.[a-zA-Z0-9_\[\]\.]+",
        r"field\s+([a-zA-Z0-9_\.\[\]]+)",
        r"at\s+([a-zA-Z0-9_\.\[\]]+)",
    ]
    for pattern in patterns:
        m = re.search(pattern, stderr)
        if m:
            return m.group(0 if pattern.startswith("\\$") else 1)
    return None


def validate_rule_files(config_directory: Path) -> list[str]:
    errors: list[str] = []
    for rule_file in sorted(config_directory.glob("**/*.json")):
        try:
            json.loads(rule_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{rule_file}: JSON 无法解析: {exc}")
    return errors


def run_validation(binary: Path, config: Path, config_directory: Path) -> tuple[bool, str]:
    command = [
        str(binary),
        "format",
        "-w",
        "-c",
        str(config),
        "-D",
        str(config_directory),
    ]
    result = run_cmd(command)
    if result.returncode == 0:
        return True, "配置格式化与 schema 校验通过。"

    field = extract_error_field(result.stderr)
    prefix = f"失败字段: {field}. " if field else ""
    return False, f"{prefix}{suggest_schema_fix(result.stderr)}\n原始错误:\n{result.stderr.strip()}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run sing-box format validation after tests.")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--config-directory", default="config_directory")
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    config = (repo_root / args.config).resolve()
    config_directory = (repo_root / args.config_directory).resolve()

    if not args.skip_tests:
        test_result = run_cmd(["pytest", "-q"])
        if test_result.returncode != 0:
            print(test_result.stdout)
            print(test_result.stderr)
            print("测试未通过，已停止 sing-box 配置校验。")
            return test_result.returncode

    binary = discover_binary(repo_root)
    ensure_executable(binary)

    parse_errors = validate_rule_files(config_directory)
    if parse_errors:
        print("规则文件存在 JSON 解析错误:")
        for error in parse_errors:
            print("-", error)
        return 2

    ok, message = run_validation(binary, config, config_directory)
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
