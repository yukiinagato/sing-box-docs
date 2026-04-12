import json
import socket
import subprocess
import time
from pathlib import Path

import pytest

from tools.config_generation import generate_tunnel_pair
from tools.run_singbox_validation import discover_binary


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise TimeoutError(f"port {port} not ready")


def _wait_log_contains(path: Path, needle: str, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        if needle in text:
            return
        time.sleep(0.1)
    raise TimeoutError(f"log did not contain expected message: {needle}")


@pytest.mark.integration
def test_local_tunnel_traffic(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    sing_box = discover_binary(repo_root)

    target_port = _free_port()
    server_port = _free_port()
    client_port = _free_port()

    server_cfg, client_cfg = generate_tunnel_pair(
        server_port=server_port,
        client_port=client_port,
        password="0123456789abcdef0123456789abcdef",
    )

    server_path = tmp_path / "server.json"
    client_path = tmp_path / "client.json"
    server_path.write_text(json.dumps(server_cfg), encoding="utf-8")
    client_path.write_text(json.dumps(client_cfg), encoding="utf-8")

    target_log = tmp_path / "target.log"
    server_log = tmp_path / "server.log"
    client_log = tmp_path / "client.log"

    procs = []
    try:
        target = subprocess.Popen(
            ["python", "-m", "http.server", str(target_port), "--bind", "127.0.0.1"],
            stdout=target_log.open("w"),
            stderr=subprocess.STDOUT,
        )
        procs.append(target)

        server = subprocess.Popen(
            [str(sing_box), "run", "-c", str(server_path)],
            stdout=server_log.open("w"),
            stderr=subprocess.STDOUT,
        )
        procs.append(server)

        client = subprocess.Popen(
            [str(sing_box), "run", "-c", str(client_path)],
            stdout=client_log.open("w"),
            stderr=subprocess.STDOUT,
        )
        procs.append(client)

        _wait_port(target_port)
        _wait_port(server_port)
        _wait_port(client_port)

        probe = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                "8",
                "--proxy",
                f"http://127.0.0.1:{client_port}",
                f"http://127.0.0.1:{target_port}",
            ],
            capture_output=True,
            text=True,
        )
        assert probe.returncode == 0, probe.stderr
        assert "<html" in probe.stdout.lower()
        _wait_log_contains(server_log, "inbound/shadowsocks[ss-in]: inbound connection from")
    finally:
        for proc in reversed(procs):
            proc.kill()
        for proc in reversed(procs):
            proc.wait(timeout=5)
