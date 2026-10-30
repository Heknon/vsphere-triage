"""The words a model reads agree with the tools it can call.

The skill, the README, the docs, the server instructions and every tool
description name tools, arguments, states and flags. A name that drifts from
the code sends a model after a tool or a field that is not there, so each is
checked against the tool surface the server actually registers.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import pytest

from vsphere_triage import checks
from vsphere_triage.config import Settings
from vsphere_triage.server import INSTRUCTIONS, build_server

ROOT = Path(__file__).resolve().parents[1]
CALL = re.compile(r"\b([a-z]+(?:_[a-z0-9]+)+)\(([^()]*)\)")
NAMED_ARGUMENT = re.compile(r"\b([a-z_]+)\s*=")
ARG_LINE = re.compile(r"^ {4}([a-z_]+):", re.MULTILINE)


@pytest.fixture(scope="module")
def tools() -> dict[str, Any]:
    # Every optional source configured, so every tool is registered.
    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
            "VSPHERE_VROPS_URL": "https://vrops.example",
            "VSPHERE_VROPS_USERNAME": "u",
            "VSPHERE_VROPS_PASSWORD": "p",
            "VSPHERE_POWERFLEX_URL": "https://pflex.example",
            "VSPHERE_POWERFLEX_USERNAME": "u",
            "VSPHERE_POWERFLEX_PASSWORD": "p",
        }
    )
    return {tool.name: tool for tool in asyncio.run(build_server(settings).list_tools())}


@pytest.fixture(scope="module")
def texts(tools: dict[str, Any]) -> dict[str, str]:
    files = [
        *sorted((ROOT / "skills" / "vm-incident").rglob("*.md")),
        ROOT / "README.md",
        *sorted((ROOT / "docs").rglob("*.md")),
    ]
    read = {str(path.relative_to(ROOT)): path.read_text() for path in files}
    read["server instructions"] = INSTRUCTIONS
    read |= {f"{name} description": tool.description or "" for name, tool in tools.items()}
    return read


def test_every_tool_call_written_down_names_a_tool_and_its_arguments(
    tools: dict[str, Any], texts: dict[str, str]
) -> None:
    wrong = []
    for source, text in texts.items():
        for match in CALL.finditer(text):
            name, arguments = match.groups()
            if name not in tools:
                wrong.append(f"{source}: {name}() is not a tool")
                continue
            accepted = set(tools[name].input_schema.get("properties", {}))
            wrong.extend(
                f"{source}: {name}() has no argument {argument!r}"
                for argument in NAMED_ARGUMENT.findall(arguments)
                if argument not in accepted
            )

    assert not wrong, "\n".join(wrong)


def test_every_tool_documents_exactly_its_arguments(tools: dict[str, Any]) -> None:
    wrong = []
    for name, tool in tools.items():
        accepted = set(tool.input_schema.get("properties", {}))
        description = tool.description or ""
        documented = set(ARG_LINE.findall(description.split("Args:")[1])) if "Args:" in description else set()
        if documented != accepted:
            wrong.append(f"{name}: documents {sorted(documented)}, takes {sorted(accepted)}")

    assert not wrong, "\n".join(wrong)


def test_the_skill_explains_every_state_a_verdict_can_have() -> None:
    table = (ROOT / "skills" / "vm-incident" / "core" / "causes.md").read_text()

    missing = [state for state in checks.MEANING if state != "healthy" and f"`{state}`" not in table]

    assert not missing, missing


def test_the_skill_names_only_flags_that_exist() -> None:
    words = "\n".join(path.read_text() for path in (ROOT / "skills" / "vm-incident").rglob("*.md"))
    flag_like = set(re.findall(r"`([a-z]+(?:_[a-z]+)+)` flag", words))

    assert flag_like <= set(checks.FLAG_MEANING), flag_like - set(checks.FLAG_MEANING)
