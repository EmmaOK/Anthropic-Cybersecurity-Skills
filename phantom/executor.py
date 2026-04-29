"""
executor.py — Subprocess runner for skill agent.py scripts.

Locates and executes the agent.py script for a given skill,
captures output, and returns it as a string for Claude to interpret.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
TIMEOUT_SECONDS = 60


def run_agent(skill_name: str, args: list[str]) -> str:
    """
    Execute skills/{skill_name}/scripts/agent.py with the given args.

    Returns the combined stdout+stderr as a string.
    Returns an error message string if the script is missing or times out.
    """
    agent_path = ROOT / "skills" / skill_name / "scripts" / "agent.py"

    if not agent_path.exists():
        return (
            f"[Error] No agent.py found for skill '{skill_name}'.\n"
            f"Expected path: {agent_path}\n"
            "This skill may not have an executable script."
        )

    cmd = [sys.executable, str(agent_path)] + [str(a) for a in args]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            cwd=str(ROOT),
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[stderr]\n{result.stderr}"
        if result.returncode != 0:
            output += f"\n[Exit code: {result.returncode}]"
        return output.strip() or "[No output produced]"

    except subprocess.TimeoutExpired:
        return (
            f"[Error] Script timed out after {TIMEOUT_SECONDS}s.\n"
            "The operation may require more time or the target is unreachable."
        )
    except Exception as e:
        return f"[Error] Failed to execute agent.py: {e}"
