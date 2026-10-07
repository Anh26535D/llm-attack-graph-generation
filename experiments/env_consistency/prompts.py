"""Prompt construction for E1 cases.

Prompts reuse CrystalBall's own CVE_CONTEXT_PROMPT verbatim and append (a) a
description of the target system and (b) the eight CVE descriptions, each tagged with
its CVE ID so nodes can be traced back. Two instruction variants:

plain      -- CrystalBall's instruction unchanged (it never asks the model to filter by
              the target system).
env_aware  -- the same prompt plus one sentence telling the model to include only
              vulnerabilities that are exploitable on the described system.

Both include all eight CVEs regardless of the environment, so most cases contain
CVEs that do NOT apply; ignoring that is itself a consistency failure.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from crystalball.generator import CVE_CONTEXT_PROMPT

from .envs import INTERVENTIONS, Env, build_env

ENV_AWARE_SENTENCE = (
    "Include only vulnerabilities that are actually exploitable on the target system "
    "described below, given its software versions, configuration and network position. "
)
VARIANTS = ("plain", "env_aware")
CVE_DIR = Path(__file__).resolve().parents[2] / "data" / "cve_official"


def load_cve_descriptions(cve_dir: Path = CVE_DIR) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(cve_dir.glob("CVE-*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        for item in record["containers"]["cna"]["descriptions"]:
            if str(item.get("lang", "")).lower().startswith("en"):
                out[record["cveMetadata"]["cveId"]] = item["value"].strip()
                break
    return out


def render_env(env: Env, intervention_note: str | None = None) -> str:
    lines = [f"Target system: {env.title}."]
    for host in env.hosts.values():
        lines.append(f"- Host '{host.name}': {host.description}.")
        for service, version in host.services.items():
            lines.append(f"    * {service} version {version}")
        facts = []
        for flag, value in host.flags.items():
            facts.append(f"{flag.replace('_', ' ')}: {'yes' if value else 'no'}")
        if facts:
            lines.append("    * facts: " + "; ".join(facts))
        lines.append(
            "    * reachable directly from the internet: "
            + ("yes" if host.internet_exposed else "no")
        )
        lines.append(
            "    * attacker has physical access to the device: "
            + ("yes" if host.physical_access else "no")
        )
        lines.append(
            "    * attacker has optical line of sight to the device: "
            + ("yes" if host.line_of_sight else "no")
        )
    for src, dst in sorted(env.links):
        lines.append(f"- Network: '{src}' can open connections to '{dst}'.")
    if not env.links and len(env.hosts) > 1:
        lines.append("- Network: no host can open connections to another host.")
    lines.append("- Attacker starts on the internet with no access to any host.")
    if intervention_note:
        lines.append(f"- Change from the previous configuration: {intervention_note}")
    return "\n".join(lines)


@dataclass(frozen=True)
class Case:
    case_id: str
    env_id: str
    state: str  # "base" or an intervention name
    variant: str
    prompt: str


def build_prompt(env_id: str, state: str, variant: str, descriptions: dict[str, str]) -> str:
    if variant not in VARIANTS:
        raise ValueError(f"Unknown variant: {variant}")
    note = None if state == "base" else INTERVENTIONS[env_id][state].description
    env = build_env(env_id, None if state == "base" else state)
    # The facts in render_env already describe the changed state; the note only
    # states what changed so the model cannot miss it.
    body = [
        CVE_CONTEXT_PROMPT.rstrip("\n") + " "
        + (ENV_AWARE_SENTENCE if variant == "env_aware" else ""),
        "",
        render_env(env, note),
        "",
        "Vulnerability information:",
    ]
    body.extend(f"{cve_id}: {text}" for cve_id, text in sorted(descriptions.items()))
    return "\n".join(body).strip() + "\n"


def build_cases(
    descriptions: dict[str, str],
    env_ids: list[str] | None = None,
    variants: list[str] | None = None,
) -> list[Case]:
    cases: list[Case] = []
    for env_id in env_ids or sorted(INTERVENTIONS):
        for state in ["base", *INTERVENTIONS[env_id]]:
            for variant in variants or list(VARIANTS):
                cases.append(
                    Case(
                        case_id=f"{env_id}.{state}.{variant}",
                        env_id=env_id,
                        state=state,
                        variant=variant,
                        prompt=build_prompt(env_id, state, variant, descriptions),
                    )
                )
    return cases
