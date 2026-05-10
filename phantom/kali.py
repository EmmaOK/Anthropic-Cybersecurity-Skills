"""
kali.py — SSH executor for Kali Linux VM at 192.168.64.2.

Runs shell commands on the Kali VM and returns output.
Requires: passwordless SSH key at ~/.ssh/id_ed25519
"""

import subprocess
from pathlib import Path

KALI_HOST = "192.168.64.2"
KALI_USER = "emmanuel"
SSH_KEY = str(Path.home() / ".ssh" / "id_ed25519")
DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 600

_SSH_OPTS = [
    "-i", SSH_KEY,
    "-o", "StrictHostKeyChecking=no",
    "-o", "ConnectTimeout=10",
    "-o", "BatchMode=yes",
]


def run_on_kali(command: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Execute a shell command on the Kali VM via SSH.
    Returns {"stdout", "stderr", "exit_code", "error"}.
    """
    timeout = min(timeout, MAX_TIMEOUT)
    ssh_cmd = ["ssh"] + _SSH_OPTS + [f"{KALI_USER}@{KALI_HOST}", command]
    try:
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "exit_code": result.returncode,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "", "exit_code": -1,
                "error": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"stdout": "", "stderr": "", "exit_code": -1, "error": str(e)}


def kali_reachable() -> bool:
    """Returns True if the Kali VM responds to a quick SSH probe."""
    result = subprocess.run(
        ["ssh"] + _SSH_OPTS + [f"{KALI_USER}@{KALI_HOST}", "echo ok"],
        capture_output=True, timeout=12,
    )
    return result.returncode == 0
