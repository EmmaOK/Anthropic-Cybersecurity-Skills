"""
tools.py — Claude tool definitions for Phantom.

Four tools:
  - search_skills: keyword/technique search across the skill library
  - load_skill: load full SKILL.md content for a skill
  - run_skill_agent: execute a skill's agent.py script
  - write_file: write generated content to a file on disk
"""

TOOLS = [
    {
        "name": "search_skills",
        "description": (
            "Search the cybersecurity skill library by keyword, tool name, or MITRE ATT&CK "
            "tactic/technique ID (e.g. 'T1003', 'reconnaissance', 'DCSync', 'BloodHound'). "
            "Returns up to 5 matching skills with their names and descriptions. "
            "Always search before loading to find the best match."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Search term. Examples: 'external reconnaissance', 'privilege escalation', "
                        "'T1003.006', 'pass the ticket', 'BloodHound', 'C2 infrastructure'"
                    ),
                }
            },
            "required": ["query"],
        },
    },
    {
        "name": "load_skill",
        "description": (
            "Load the full workflow, commands, prerequisites, and framework mappings for a specific "
            "skill by its exact kebab-case name. Use the name returned by search_skills. "
            "Load the skill before walking the user through any procedure."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "skill_name": {
                    "type": "string",
                    "description": (
                        "Exact skill name in kebab-case, as returned by search_skills. "
                        "Example: 'conducting-external-reconnaissance-with-osint'"
                    ),
                }
            },
            "required": ["skill_name"],
        },
    },
    {
        "name": "run_skill_agent",
        "description": (
            "Execute the skill's agent.py script as a subprocess with the provided CLI arguments. "
            "Only use this when the user explicitly asks to run or execute a script or tool. "
            "Always confirm the target and arguments with the user before calling this. "
            "This runs real code — only use in authorized lab/test environments."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "skill_name": {
                    "type": "string",
                    "description": "Exact skill name in kebab-case.",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "CLI arguments to pass to agent.py. "
                        "Example: ['--domain', 'lab.local', '--output', 'report.json']"
                    ),
                },
            },
            "required": ["skill_name", "args"],
        },
    },
    {
        "name": "write_file",
        "description": (
            "Write generated content (YAML configs, pipeline files, scripts, reports, checklists) "
            "to a file on disk. Use this when the user asks Phantom to save, create, or write "
            "output to a file. Always show the user the content before writing."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "File path relative to the project root. "
                        "Examples: 'bitbucket-pipelines.yml', 'reports/recon.md', "
                        "'scripts/enum.py'"
                    ),
                },
                "content": {
                    "type": "string",
                    "description": "Full file content to write.",
                },
            },
            "required": ["path", "content"],
        },
    },
]
