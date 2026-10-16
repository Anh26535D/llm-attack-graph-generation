"""Conservative capability bridges with explicit, three-valued prerequisites."""

from __future__ import annotations

from copy import deepcopy

from ..postprocess import AttackGraph
from .conditions import CONDITIONS
from .evidence import EnvironmentState, EvidenceStore, RULESET_VERSION, digest


def edge_instances(graph: AttackGraph) -> list[dict]:
    """Ordinal identity preserves repeated IDs, identical edges and parallel edges."""
    return [{"edge_id": f"edge-{i:04d}", "original_edge_id": edge.get("id"),
             "index": i - 1, "edge": deepcopy(edge)} for i, edge in enumerate(graph.edges, 1)]


class OfflineValidator:
    def __init__(self, evidence: EvidenceStore, environment: EnvironmentState | None = None):
        self.store = evidence
        self.environment = environment or EnvironmentState({}, {"kind": "absent"})

    def validate(self, graph: AttackGraph) -> list[dict]:
        by_id = {}
        for node in graph.nodes:
            if not isinstance(node, dict) or "id" not in node:
                raise ValueError("Every node must be an object with an id")
            key = str(node["id"])
            if key in by_id:
                raise ValueError(f"Ambiguous duplicate node id: {key}")
            by_id[key] = node
        if any(not isinstance(e, dict) for e in graph.edges):
            raise ValueError("Every edge must be an object")
        return [self._edge(instance, by_id) for instance in edge_instances(graph)]

    def _edge(self, instance: dict, by_id: dict) -> dict:
        edge = instance["edge"]
        source = by_id.get(str(edge.get("from", edge.get("source"))))
        target = by_id.get(str(edge.get("to", edge.get("target"))))
        result = {**instance, "source_node": deepcopy(source), "target_node": deepcopy(target),
                  "claim": str(edge.get("label", "")), "ruleset": RULESET_VERSION,
                  "source_mapping": self.store.mapping(source or {}),
                  "target_mapping": self.store.mapping(target or {}),
                  "evidence": {}, "checks": [], "missing_conditions": [], "assumptions": [],
                  "hard_conflicts": [], "candidate_bridge": None, "status": "unknown"}
        if source is None or target is None:
            result["reason"] = "An endpoint is absent from the original node set."
            return result
        for role in ("source", "target"):
            mapping = result[f"{role}_mapping"]
            if mapping["status"] == "mapped":
                result["evidence"][role] = self.store.evidence(mapping["cve_id"])
        if any(result[k]["status"] != "mapped" for k in ("source_mapping", "target_mapping")):
            result["reason"] = "CVE identity is missing, outside the corpus, or ambiguous."
            result["missing_conditions"] = ["unique_source_and_target_CVE_mapping"]
            return result
        source_id, target_id = (result[k]["cve_id"] for k in ("source_mapping", "target_mapping"))
        src, dst = self.store.evidence(source_id), self.store.evidence(target_id)
        result["evidence"] = {"source": src, "target": dst}
        result["checks"].append({"rule": "identity", "outcome": "pass", "ids": [source_id, target_id]})
        result["assumptions"].append("Generated node pre/postconditions and edge text are claims, not evidence.")
        for role, node, evidence in (("source", source, src), ("target", target, dst)):
            self._applicability(role, node, evidence, result)
        effects, requirements = src["facts"]["effects"], dst["facts"]["requirements"]
        if "local_user" in requirements and "code_execution" in effects:
            result["candidate_bridge"] = "code_execution_to_local_user"
        elif "local_user" in requirements and "possible_code_execution" in effects:
            result["candidate_bridge"] = "possible_execution_to_local_user"
            result["missing_conditions"].append("source_code_execution_is_only_possible")
        elif "authentication" in requirements and ({"file_read", "admin", "code_execution"} & effects.keys()):
            result["candidate_bridge"] = "possible_credential_access"
            result["missing_conditions"].append("readable_valid_target_application_credentials")
            if "code_execution" in effects:
                result["missing_conditions"].append("source_process_can_read_or_modify_target_authentication_material")
        elif "audio_equipment" in requirements and ({"code_execution", "admin"} & effects.keys()):
            result["candidate_bridge"] = "possible_audio_activation"
            result["missing_conditions"].append("command_control_of_target_audio_playback")
        else:
            result["missing_conditions"].append("no_description_grounded_capability_bridge_for_this_claim")

        source_host, _ = self.environment.host_for(source)
        target_host, _ = self.environment.host_for(target)
        if not source_host or not target_host:
            result["missing_conditions"].append("externally_verified_source_target_host_relationship")
        elif "local_user" in requirements:
            if source_host != target_host:
                result["hard_conflicts"].append("Source execution is on a different host from target local access.")
            else:
                result["checks"].append({"rule": "same_host_local_access", "outcome": "pass"})
        elif CONDITIONS.get(target_id) and CONDITIONS[target_id].access == "network":
            _, target_state = self.environment.host_for(target)
            direct = target_state.get("network_access", target_state.get("internet_exposed"))
            host_control = bool({"code_execution", "admin"} & effects.keys())
            possible_control = "possible_code_execution" in effects
            reachable = self.environment.reachability(source_host, target_host) if host_control else None
            if direct is True or reachable is True:
                result["checks"].append({"rule": "target_network_access", "outcome": "pass",
                                         "vantage": "initial_attacker" if direct is True else "source_host"})
            elif direct is False and (not host_control and not possible_control or reachable is False):
                result["hard_conflicts"].append("Direct target network access is denied and the source provides no verified reachable foothold.")
            else:
                # A blocked source->target link does not establish that an
                # independently located initial attacker cannot reach the target.
                result["missing_conditions"].append("target_network_access_from_attacker_or_verified_source_foothold")

        # A full natural-language claim can include credential theft, SYSTEM, sandbox
        # escape, etc. Only a bounded canonical relation can be proven by this rule.
        canonical = (edge.get("relation") == "local_execution_enables_local_exploit"
                     and result["claim"] == "Local code execution enables local exploitation.")
        if not canonical:
            result["missing_conditions"].append("full_edge_claim_entailment_requires_semantic_review")
        if result["hard_conflicts"]:
            result.update(status="contradicted", reason="Observed environment violates a necessary prerequisite.")
        elif not src["facts"]["effects"] or not dst["facts"]["requirements"]:
            result["reason"] = "No adequate description-grounded effect or prerequisite is available."
        elif result["candidate_bridge"]:
            if canonical and not result["missing_conditions"] and result["candidate_bridge"] == "code_execution_to_local_user":
                result.update(status="supported", reason="Quoted code execution satisfies local access on the verified same host; applicability is checked.")
            else:
                result.update(status="conditional", reason="A bounded capability bridge is plausible; listed prerequisites or claim details remain unverified.")
                result["assumptions"].append("The candidate bridge is an inference, not an observed causal transition.")
        elif edge.get("relation") == "local_execution_enables_local_exploit" and set(effects) <= {"file_read", "audio_recovery"}:
            result.update(status="unsupported", reason="The canonical local-execution claim requires a capability the source description does not establish.")
        else:
            result["reason"] = "The descriptions do not establish the claimed causal bridge; absence of evidence is not contradiction."
        result["missing_conditions"] = sorted(set(result["missing_conditions"]))
        result["checks"].append({"rule": "capability_bridge", "outcome": result["status"],
                                 "bridge": result["candidate_bridge"]})
        return result

    def _applicability(self, role: str, node: dict, evidence: dict, result: dict) -> None:
        cve_id = evidence["cve_id"]
        cond = CONDITIONS.get(cve_id)
        name, host = self.environment.host_for(node)
        missing = result["missing_conditions"]
        conflicts = result["hard_conflicts"]
        if cond is None:
            missing.append(f"{role}:unmodeled_applicability")
            return
        if not name or not host:
            missing.append(f"{role}:product_platform_version_and_prerequisites")
            return
        platforms = evidence["facts"].get("platforms", {})
        platform = host.get("platform")
        if platforms:
            if platform is None:
                missing.append(f"{role}:observed_platform")
            elif platform not in platforms:
                conflicts.append(f"{role}: observed platform {platform} conflicts with {sorted(platforms)}.")
        version = host.get("services", {}).get(cond.service)
        if version is None:
            if host.get("services_complete") is True:
                conflicts.append(f"{role}: required product {cond.service} is absent in the observed complete inventory.")
            else:
                missing.append(f"{role}:installed_{cond.service}_version")
        else:
            try:
                affected = cond.version_affected(str(version))
            except (ValueError, TypeError):
                missing.append(f"{role}:unparseable_version")
            else:
                if not affected:
                    conflicts.append(f"{role}: {cond.service} {version} violates the affected version rule.")
                result["checks"].append({"rule": "product_version", "role": role,
                                         "service": cond.service, "observed": version,
                                         "outcome": "pass" if affected else "conflict",
                                         "provenance": evidence["provenance"]})
        flags = host.get("flags", {})
        for flag, expected in cond.requires:
            actual = flags.get(flag)
            if not isinstance(actual, bool):
                missing.append(f"{role}:{flag}")
            elif actual != expected:
                conflicts.append(f"{role}: observed {flag}={actual} violates the prerequisite.")
        # Local target access can be supplied by the candidate bridge, but source
        # applicability must hold from externally observed initial state.
        access_flag = {"network": "network_access", "physical": "physical_access",
                       "line_of_sight": "line_of_sight", "local": "local_access"}[cond.access]
        if role == "target" and cond.access in {"local", "network"}:
            return
        actual = host.get(access_flag)
        if cond.access == "network" and actual is None:
            # E1's network assumption for the default-password CVE is explicitly
            # an interpretation. A recorded network observation still has provenance.
            actual = host.get("internet_exposed")
        if actual is False:
            conflicts.append(f"{role}: observed {access_flag}=false.")
        elif actual is not True:
            missing.append(f"{role}:{access_flag}")

    def provenance(self) -> dict:
        return {"dataset_digest": self.store.dataset_digest, "ruleset": RULESET_VERSION,
                "environment": self.environment.provenance,
                "environment_digest": digest(self.environment.data)}
