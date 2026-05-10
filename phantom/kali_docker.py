"""
kali_docker.py — Ephemeral Kali Docker executor for Phantom.

Each command runs in an isolated container destroyed on completion.
Uses phantom-kali:latest (built from Dockerfile.kali) with all tools
pre-installed. Falls back to kalilinux/kali-rolling if image not built.

Build image:   docker build -t phantom-kali:latest -f phantom/Dockerfile.kali phantom/
Check status:  docker_available(), phantom_image_exists()
"""

import subprocess
import uuid
from pathlib import Path

PHANTOM_IMAGE = "phantom-kali:latest"
FALLBACK_IMAGE = "kalilinux/kali-rolling"
DOCKERFILE = Path(__file__).parent / "Dockerfile.kali"
DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 600


def docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def phantom_image_exists() -> bool:
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", PHANTOM_IMAGE],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


def build_image() -> dict:
    """Build phantom-kali:latest from Dockerfile.kali. Takes ~10 minutes first time."""
    if not DOCKERFILE.exists():
        return {"success": False, "error": f"Dockerfile not found: {DOCKERFILE}"}
    result = subprocess.run(
        ["docker", "build", "-t", PHANTOM_IMAGE, "-f", str(DOCKERFILE), str(DOCKERFILE.parent)],
        capture_output=True, text=True, timeout=1800,
    )
    if result.returncode == 0:
        return {"success": True, "image": PHANTOM_IMAGE}
    return {"success": False, "error": result.stderr[-2000:]}


def run_in_container(
    command: str,
    timeout: int = DEFAULT_TIMEOUT,
    network: str = "host",
    workspace_path: str | None = None,
    label: str | None = None,
) -> dict:
    """
    Run a shell command in an ephemeral Kali container.
    Container is --rm (auto-deleted on exit).
    Returns {"stdout", "stderr", "exit_code", "error", "container_id", "image"}.
    """
    timeout = min(timeout, MAX_TIMEOUT)
    container_id = f"phantom-{label or uuid.uuid4().hex[:8]}"
    image = PHANTOM_IMAGE if phantom_image_exists() else FALLBACK_IMAGE

    docker_cmd = [
        "docker", "run", "--rm",
        "--name", container_id,
        f"--network={network}",
    ]

    if workspace_path:
        docker_cmd += ["-v", f"{workspace_path}:/workspace", "-w", "/workspace"]

    docker_cmd += [image, "bash", "-c", command]

    try:
        result = subprocess.run(
            docker_cmd, capture_output=True, text=True, timeout=timeout,
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "exit_code": result.returncode,
            "error": None,
            "container_id": container_id,
            "image": image,
        }
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", container_id], capture_output=True)
        return {
            "stdout": "", "stderr": "", "exit_code": -1,
            "error": f"Timed out after {timeout}s — container {container_id} killed",
            "container_id": container_id, "image": image,
        }
    except FileNotFoundError:
        return {
            "stdout": "", "stderr": "", "exit_code": -1,
            "error": "Docker not found. Install Docker Desktop for Mac.",
            "container_id": container_id, "image": image,
        }
    except Exception as e:
        return {
            "stdout": "", "stderr": "", "exit_code": -1,
            "error": str(e), "container_id": container_id, "image": image,
        }


def status() -> dict:
    """Return Docker + image availability summary."""
    da = docker_available()
    return {
        "docker_available": da,
        "phantom_image_built": phantom_image_exists() if da else False,
        "fallback_image": FALLBACK_IMAGE,
        "build_command": f"docker build -t {PHANTOM_IMAGE} -f phantom/Dockerfile.kali phantom/",
    }
