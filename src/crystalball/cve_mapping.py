"""Shared H1 node identity hints; these map identities, never edge labels."""

import json
import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
LABEL_KEYWORDS = {
    "CVE-2019-20354": ("pisignage",),
    "CVE-2019-3562": ("oculus browser",),
    "CVE-2020-1885": ("ovrredir",),
    "CVE-2020-24572": ("raspap",),
    "CVE-2021-24038": ("ovrservicelauncher",),
    "CVE-2021-38545": ("glowworm",),
    "CVE-2021-38759": ("default password",),
    "CVE-2022-21819": ("jetson", "iommu"),
}


def identity_candidates(node: dict) -> tuple[list[str], str]:
    explicit = sorted({m.upper() for m in CVE_RE.findall(json.dumps(node))})
    if explicit:
        return explicit, "explicit_id"
    label = str(node.get("label", "")).lower()
    hits = {cve for cve, words in LABEL_KEYWORDS.items() if any(w in label for w in words)}
    if ("raspberry pi os" in label and "default" in label
            and ("password" in label or "credential" in label)):
        hits.add("CVE-2021-38759")
    return sorted(hits), "label_hint"
