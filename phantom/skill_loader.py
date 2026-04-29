"""
skill_loader.py — Skill discovery and loading for Phantom.

Reads index.json for fast search across all 754 skills,
then loads full SKILL.md content on demand.
"""

import json
import re
from pathlib import Path

# Project root is one level up from this file
ROOT = Path(__file__).parent.parent
INDEX_PATH = ROOT / "index.json"


def _load_index() -> list[dict]:
    """Load all skills from index.json."""
    with open(INDEX_PATH, "r") as f:
        data = json.load(f)
    return data["skills"]


# Load once at import time
_SKILLS: list[dict] = _load_index()


def search_skills(query: str, top_n: int = 5) -> list[dict]:
    """
    Search skills by keyword against name and description.
    Also matches ATT&CK technique IDs (e.g. T1003, T1059.001).
    Returns up to top_n results with name, description, path.
    """
    query_lower = query.lower()
    terms = query_lower.split()

    scored = []
    for skill in _SKILLS:
        name = skill["name"].lower()
        desc = (skill.get("description") or "").lower()
        combined = name + " " + desc

        score = 0
        for term in terms:
            if term in name:
                score += 3  # name match weighted higher
            elif term in desc:
                score += 1

        # Boost exact ATT&CK technique ID matches (e.g. t1003)
        attack_pattern = re.compile(r't\d{4}(\.\d{3})?')
        for term in terms:
            if attack_pattern.match(term):
                if term in combined:
                    score += 5

        if score > 0:
            scored.append((score, skill))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [s for _, s in scored[:top_n]]


def load_skill(skill_name: str) -> str:
    """
    Load the full SKILL.md content for a skill by name.
    Returns the raw markdown string (YAML frontmatter + body).
    Returns an error string if not found.
    """
    skill_path = ROOT / "skills" / skill_name / "SKILL.md"
    if not skill_path.exists():
        return f"[Error] Skill '{skill_name}' not found at {skill_path}"

    return skill_path.read_text(encoding="utf-8")


def load_skill_frontmatter(skill_name: str) -> dict:
    """
    Parse only the YAML frontmatter from a SKILL.md file.
    Returns a dict of key-value pairs. Uses stdlib only (no PyYAML).
    """
    content = load_skill(skill_name)
    if content.startswith("[Error]"):
        return {}

    match = re.match(r'^---\n(.*?)\n---', content, re.DOTALL)
    if not match:
        return {}

    frontmatter: dict = {}
    yaml_block = match.group(1)

    current_key = None
    current_list: list = []

    for line in yaml_block.splitlines():
        # List item
        if line.startswith("- "):
            if current_key:
                current_list.append(line[2:].strip())
            continue

        # Key: value pair
        kv_match = re.match(r'^(\w[\w_-]*):\s*(.*)', line)
        if kv_match:
            # Save previous key if it was accumulating a list
            if current_key and current_list:
                frontmatter[current_key] = current_list
                current_list = []

            current_key = kv_match.group(1)
            value = kv_match.group(2).strip().strip("'\"")

            if value:
                frontmatter[current_key] = value
                current_key = None  # not a list key
            else:
                # Value is on next lines as a list
                current_list = []

    # Flush last list
    if current_key and current_list:
        frontmatter[current_key] = current_list

    return frontmatter


def get_skill_path(skill_name: str) -> Path:
    """Return the Path to a skill's directory."""
    return ROOT / "skills" / skill_name


def list_skill_names() -> list[str]:
    """Return all skill names."""
    return [s["name"] for s in _SKILLS]
