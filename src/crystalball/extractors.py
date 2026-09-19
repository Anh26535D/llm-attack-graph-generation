"""Property extraction step of Algorithm 1 (Preprocess CVE), lines 13-15:

    prompt = "provide the affected product name, platform and version if
    present using a key called ProductInfo, platform using a key called
    Platform, the problem type using a key called ProblemType in a single
    json from vulnerability information given below. ProductInfo should
    have properties ProductName and Version. Version should have properties
    VersionNumber and Qualifier whose value would be <=, >=, == etc." + description

Two interchangeable extractors implement this step:

* `HeuristicExtractor` -- no LLM call. Prefers the CVE record's own
  structured `affected` array (vendor/product/versions/platforms) per the
  CVE Record Format v5 schema, and falls back to light regex heuristics over
  the free-text description otherwise. This lets the whole pipeline run
  with zero API keys, at the cost of the fine-grained accuracy an LLM gives
  (this is exactly the gap the paper identifies for why an LLM is needed).
* `LLMExtractor` -- sends the paper's exact prompt to a configured
  LLMClient and parses the JSON it returns. This is the paper's real
  method; use it by setting EXTRACTOR_BACKEND=llm and an LLM_BACKEND.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from .llm.base import LLMClient

EXTRACTION_PROMPT_TEMPLATE = (
    "provide the affected product name, platform and version if present "
    "using a key called ProductInfo, platform using a key called Platform, "
    "the problem type using a key called ProblemType in a single json from "
    "vulnerability information given below. ProductInfo should have "
    "properties ProductName and Version. Version should have properties "
    "VersionNumber and Qualifier whose value would be <=, >=, == etc. "
    "Respond with only the json.\n\n{description}"
)


@dataclass
class VersionInfo:
    version_number: str | None = None
    qualifier: str | None = None


@dataclass
class ExtractedProperties:
    product_name: str | None = None
    version: VersionInfo = field(default_factory=VersionInfo)
    platform: str | None = None
    problem_type: str | None = None


class Extractor(ABC):
    @abstractmethod
    def extract(self, description: str, cve_json: dict[str, Any]) -> ExtractedProperties: ...


_VERSION_QUALIFIER_RE = re.compile(r"(<=|>=|==|<|>)?\s*([0-9]+(?:\.[0-9]+)*)")
_BEFORE_VERSION_RE = re.compile(
    r"\bbefore\s+([0-9]+(?:\.[0-9]+)*)|\bprior to\s+([0-9]+(?:\.[0-9]+)*)|through\s+([0-9]+(?:\.[0-9]+)*)",
    re.IGNORECASE,
)
_PLATFORM_KEYWORDS = [
    "Windows",
    "Linux",
    "macOS",
    "Android",
    "iOS",
    "Raspberry Pi OS",
]


class HeuristicExtractor(Extractor):
    """Dependency- and API-key-free fallback. See module docstring."""

    def extract(self, description: str, cve_json: dict[str, Any]) -> ExtractedProperties:
        props = ExtractedProperties()

        affected = (
            cve_json.get("containers", {}).get("cna", {}).get("affected", [])
            if cve_json
            else []
        )
        if affected:
            first = affected[0]
            product = first.get("product")
            vendor = first.get("vendor")
            if product and product != "n/a":
                props.product_name = product
            elif vendor and vendor != "n/a":
                props.product_name = vendor

            platforms = first.get("platforms") or []
            if platforms:
                props.platform = ", ".join(platforms)

            versions = first.get("versions") or []
            if versions:
                v0 = versions[0]
                props.version.version_number = v0.get("version")
                props.version.qualifier = v0.get("lessThan") and "<" or v0.get("versionType")

            problem_types = cve_json.get("containers", {}).get("cna", {}).get("problemTypes", [])
            if problem_types:
                descs = problem_types[0].get("descriptions", [])
                if descs:
                    props.problem_type = descs[0].get("description")

        if not props.product_name:
            props.product_name = self._guess_product_name(description)

        if not props.platform:
            for kw in _PLATFORM_KEYWORDS:
                if re.search(rf"\b{re.escape(kw)}\b", description, re.IGNORECASE):
                    props.platform = kw
                    break

        if not props.version.version_number:
            m = _BEFORE_VERSION_RE.search(description)
            if m:
                version = next(g for g in m.groups() if g)
                props.version.version_number = version
                props.version.qualifier = "<"

        return props

    @staticmethod
    def _guess_product_name(description: str) -> str | None:
        # "<Product> <version> allows ..." / "in <Product> before ..." patterns.
        m = re.search(r"\bin ([A-Z][\w.\- ]{2,40}?)\s+(?:before|version|through|prior)", description)
        if m:
            return m.group(1).strip()
        # Fall back to the first capitalized noun phrase in the sentence.
        m = re.search(r"([A-Z][\w.]*(?:\s+[A-Z][\w.]*){0,3})", description)
        return m.group(1).strip() if m else None


def _extract_json_object(text: str) -> dict[str, Any]:
    """LLM responses sometimes wrap JSON in prose or markdown fences."""
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start : end + 1]
    return json.loads(text)


class LLMExtractor(Extractor):
    """Runs the paper's exact Algorithm 1 extraction prompt through an LLMClient."""

    def __init__(self, llm_client: LLMClient) -> None:
        self.llm_client = llm_client

    def extract(self, description: str, cve_json: dict[str, Any]) -> ExtractedProperties:
        prompt = EXTRACTION_PROMPT_TEMPLATE.format(description=description)
        raw = self.llm_client.complete(prompt)
        data = _extract_json_object(raw)

        product_info = data.get("ProductInfo", {}) or {}
        version = product_info.get("Version", {}) or {}
        return ExtractedProperties(
            product_name=product_info.get("ProductName"),
            version=VersionInfo(
                version_number=version.get("VersionNumber"),
                qualifier=version.get("Qualifier"),
            ),
            platform=data.get("Platform"),
            problem_type=data.get("ProblemType"),
        )


def get_extractor(backend: str, llm_client: LLMClient | None = None) -> Extractor:
    if backend == "heuristic":
        return HeuristicExtractor()
    if backend == "llm":
        if llm_client is None:
            raise ValueError("EXTRACTOR_BACKEND=llm requires an LLM client (set LLM_BACKEND).")
        return LLMExtractor(llm_client)
    raise ValueError(f"Unknown EXTRACTOR_BACKEND: {backend!r}")
