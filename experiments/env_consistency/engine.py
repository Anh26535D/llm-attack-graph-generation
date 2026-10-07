"""Reference engine: which (CVE, host) pairs are enabled in an environment?

A tiny forward-chaining fixpoint (MulVAL in spirit, a few dozen lines): start from
the attacker's initial footholds, repeatedly add every CVE whose conditions hold,
and grant the foothold its effect says. It is the explicit, auditable ground truth
for E1's *consistency* checks -- it encodes the conditions in `conditions.py`, not
real-world exploitability.
"""

from __future__ import annotations

from .conditions import CONDITIONS, LEVELS
from .envs import Env

Enabled = dict[tuple[str, str], str]  # (cve_id, host) -> effect


def _access_ok(env: Env, host_name: str, access: str, footholds: dict[str, str]) -> bool:
    host = env.hosts[host_name]
    if access == "network":
        return host.internet_exposed or any(
            (src, host_name) in env.links for src in footholds if LEVELS[footholds[src]] >= 1
        )
    if access == "local":
        return footholds.get(host_name) is not None and LEVELS[footholds[host_name]] >= 1
    if access == "physical":
        return host.physical_access
    if access == "line_of_sight":
        return host.line_of_sight
    raise ValueError(f"Unknown access type: {access}")


def applicable(env: Env, cve_id: str, host_name: str, footholds: dict[str, str]) -> bool:
    cond = CONDITIONS[cve_id]
    host = env.hosts[host_name]
    version = host.services.get(cond.service)
    if version is None or not cond.version_affected(version):
        return False
    if any(host.flags.get(flag, False) != expected for flag, expected in cond.requires):
        return False
    return _access_ok(env, host_name, cond.access, footholds)


def enabled_pairs(env: Env, footholds: dict[str, str] | None = None) -> tuple[Enabled, dict[str, str]]:
    """Fixpoint from `footholds` (default: the environment's initial footholds)."""
    held = dict(env.initial_footholds if footholds is None else footholds)
    enabled: Enabled = {}
    changed = True
    while changed:
        changed = False
        for host_name in env.hosts:
            for cve_id, cond in CONDITIONS.items():
                if (cve_id, host_name) in enabled:
                    continue
                if not applicable(env, cve_id, host_name, held):
                    continue
                enabled[(cve_id, host_name)] = cond.effect
                changed = True
                if cond.effect != "info":
                    best = held.get(host_name)
                    if best is None or LEVELS[cond.effect] > LEVELS[best]:
                        held[host_name] = cond.effect
    return enabled, held


def enabled_cves(env: Env) -> set[str]:
    return {cve for cve, _ in enabled_pairs(env)[0]}


def _single_step(env: Env, cve_id: str, footholds: dict[str, str]) -> bool:
    return any(applicable(env, cve_id, host, footholds) for host in env.hosts)


def classify_edge(env: Env, cve_from: str, cve_to: str) -> str:
    """Judge a claimed 'cve_from enables cve_to' edge against the environment.

    supported    -- cve_to cannot be exploited from the initial state alone, but can once
                    the foothold that cve_from grants is added (one step).
    redundant    -- cve_to is already exploitable from the initial state (the edge is
                    harmless but is not what makes cve_to possible).
    unsupported  -- cve_from is not enabled in the environment, or cve_to stays
                    unexploitable even with cve_from's foothold.
    """
    enabled_now, _ = enabled_pairs(env)
    from_hosts = [h for (c, h) in enabled_now if c == cve_from]
    if not from_hosts:
        return "unsupported"
    if _single_step(env, cve_to, dict(env.initial_footholds)):
        return "redundant"
    for host in from_hosts:
        effect = enabled_now[(cve_from, host)]
        if effect == "info":
            continue
        footholds = dict(env.initial_footholds)
        footholds[host] = effect
        if _single_step(env, cve_to, footholds):
            return "supported"
    return "unsupported"
