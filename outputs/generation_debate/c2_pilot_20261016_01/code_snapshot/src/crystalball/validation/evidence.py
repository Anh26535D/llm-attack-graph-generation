"""Pinned CVE evidence and partial environment state, kept separate from claims."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

from ..cve_dataset import _english_description, load_official_cve_dataset
from ..cve_mapping import identity_candidates
from .conditions import CONDITIONS

RULESET_VERSION = "evidence-validator-v1"


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":"), allow_nan=False).encode()).hexdigest()


# These are capabilities stated in descriptions, not the generous E1 effect levels.
# Modal language is retained as a possible effect, never a guaranteed foothold.
FACTS = {
    "CVE-2019-20354": {
        "effects": {"file_read": "download arbitrary files"},
        "requirements": {"authentication": "authenticated as a low-privilege user"},
        "platforms": {"raspberry_pi": "from the Raspberry Pi"},
    },
    "CVE-2019-3562": {
        "effects": {"html_injection": "inject arbitrary HTML code", "possible_code_execution": "potentially execute code"},
        "requirements": {"victim_page_visit": "A remote web page"},
    },
    "CVE-2020-1885": {
        "effects": {"file_write": "write to arbitrary files", "privilege_escalation": "gain privileges"},
        "requirements": {"local_user": "allows local users", "windows": "on Windows"},
        "platforms": {"windows": "on Windows"},
    },
    "CVE-2020-24572": {
        "effects": {"code_execution": "execute commands on the system"},
        "requirements": {"authentication": "With authenticated access"},
        "platforms": {"raspberry_pi": "underlying OS (Raspberry Pi)"},
    },
    "CVE-2021-24038": {
        "effects": {"privilege_escalation": "local privilege escalation"},
        "requirements": {"local_user": "an unprivileged process"},
    },
    "CVE-2021-38545": {
        "effects": {"audio_recovery": "recover speech signals"},
        "requirements": {"audio_equipment": "supplies power to audio-output equipment",
                         "optical_access": "via a telescope and an electro-optical sensor"},
        "platforms": {"raspberry_pi": "Raspberry Pi 3 B+ and 4 B devices"},
    },
    "CVE-2021-38759": {
        "effects": {"admin": "gain administrator privileges"},
        "requirements": {"default_password_unchanged": "If not changed"},
        "platforms": {"raspberry_pi": "Raspberry Pi OS"},
    },
    "CVE-2022-21819": {
        "effects": {"memory_read_write": "direct read/write access to the entire system address space",
                    "possible_code_execution": "could result in denial of service, code execution"},
        "requirements": {"physical_access": "physical access to the board"},
        "platforms": {"jetson": "Jetson Linux"},
    },
}


@dataclass
class EvidenceStore:
    records: dict[str, dict]
    dataset_digest: str

    @classmethod
    def load(cls, manifest: Path) -> EvidenceStore:
        dataset = load_official_cve_dataset(manifest)
        records = {}
        for entry, path in zip(dataset.records, dataset.files):
            record = json.loads(path.read_text(encoding="utf-8"))
            records[entry["cve_id"]] = {
                "cve_id": entry["cve_id"],
                "description": _english_description(record),
                "affected": record["containers"]["cna"].get("affected", []),
                "provenance": {**entry, "field": "containers.cna.descriptions[en]"},
            }
        return cls(records, dataset.digest)

    def mapping(self, node: dict) -> dict:
        candidates, method = identity_candidates(node)
        status = ("ambiguous" if len(candidates) > 1 else "mapped" if len(candidates) == 1
                  and candidates[0] in self.records else "missing")
        return {"candidates": candidates, "method": method, "status": status,
                "cve_id": candidates[0] if status == "mapped" else None}

    def evidence(self, cve_id: str) -> dict:
        record = deepcopy(self.records[cve_id])
        facts = {"effects": {}, "requirements": {}, "platforms": {}}
        for group, entries in FACTS.get(cve_id, {}).items():
            for name, quote in entries.items():
                # A rule is usable only when its quote really exists in this corpus.
                if quote in record["description"]:
                    facts[group][name] = {"quote": quote, "cve_id": cve_id,
                                          "kind": "description_evidence"}
        record["facts"] = facts
        cond = CONDITIONS.get(cve_id)
        record["applicability_rule"] = None if cond is None else {
            "service": cond.service, "access": cond.access, "note": cond.note,
            "kind": "curated_description_interpretation",
            "warning": "E1 effect levels are not guaranteed CVE postconditions",
        }
        return record


@dataclass
class EnvironmentState:
    """Partial observations: omitted fields stay unknown, including absent links."""

    data: dict
    provenance: dict

    @classmethod
    def load(cls, path: Path) -> EnvironmentState:
        raw = path.read_bytes()
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Environment must be a JSON object")
        return cls(data, {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                          "kind": "user_supplied_environment"})

    def host_for(self, node: dict) -> tuple[str | None, dict]:
        # Generated node.host is a claim. Only external node_hosts bindings are facts.
        name = self.data.get("node_hosts", {}).get(str(node.get("id")))
        return name, self.data.get("hosts", {}).get(name, {})

    def reachability(self, source: str, target: str) -> bool | None:
        if source == target:
            return True
        links = self.data.get("links", [])
        for link in links:
            if isinstance(link, dict) and link.get("from") == source and link.get("to") == target:
                value = link.get("reachable")
                return value if isinstance(value, bool) else None
            if isinstance(link, list) and link == [source, target]:
                return True
        return False if self.data.get("links_complete") is True else None
