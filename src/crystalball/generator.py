"""Algorithm 3: Generate Attack Graph(Q), plus the threat-report variant
described in Section 3 ("Input") and Appendix C.

Two prompt styles are exposed, taken verbatim from the paper:

* CVE_CONTEXT_PROMPT -- the detailed instruction used in the paper's actual
  experiments (Appendix A), which asks for id/label/precondition/
  postcondition node properties and from/to/label edge properties.
* REPORT_PROMPT -- the instruction used for threat-report inputs
  (Appendix C), which asks for id/label node properties and from/to/label
  edge properties (no pre/post-condition, since reports are prose).

`generate_attack_graph` builds the full prompt and, if an LLMClient is
supplied, calls it and post-processes the answer; otherwise it just returns
the prompt for the caller to hand to a chat UI manually.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import Settings, get_settings
from .db import Database
from .llm.base import LLMClient
from .retriever import RetrievalResult, get_context

CVE_CONTEXT_PROMPT = (
    "Create an attack graph in json format using only nodes and edges as keys "
    "from the vulnerability information given below. node should have id, "
    "label, precondition and postcondition as properties. edge should have "
    "from, to and label properties. Do not give a simplified graph. Add as "
    "much detail as possible. Incorporate all possible information in nodes "
    "and edges. Do not create separate keys for them in the json. Chain the "
    "vulnerabilities if applicable. Vulnerabilities can be chained if "
    "precondition of one vulnerability is similar to the post condition of "
    "another vulnerability. Vulnerability with matching postcondition should "
    "be ahead in the chain. Return only the json as response. Do not put any "
    "text before or after the json.\n\n"
)

REPORT_PROMPT = (
    "Create an attack graph in json format using only nodes and edges as keys "
    "from the attack scenario given below. node should have id, label, edge "
    "should have from, to and label properties. Do not give a simplified "
    "graph. Add as much detail as possible. Incorporate all possible "
    "information in nodes and edges. Do not create separate keys for them in "
    "the json. Give only the graph in json format. Do not put text before or "
    "after json.\n\n"
)

NO_CONTEXT_PROMPT_TEMPLATE = (
    "Create an attack graph in json format using only nodes and edges as keys "
    "for a system comprising of {products}."
)


@dataclass
class BuiltPrompt:
    prompt: str
    query: str
    retrieval: RetrievalResult | None = None


def build_prompt_from_products(
    products: list[str],
    db: Database,
    settings: Settings | None = None,
    use_context: bool = True,
) -> BuiltPrompt:
    """CVE-description path (Section 3, "Input": product/package names)."""
    settings = settings or get_settings()
    query = ", ".join(products)

    if not use_context:
        # Reproduces the Section 5.1 baseline experiment (Figure 6): no
        # retrieval, just a bare request naming the system's components.
        return BuiltPrompt(prompt=NO_CONTEXT_PROMPT_TEMPLATE.format(products=query), query=query)

    retrieval = get_context(products, db, settings=settings)
    prompt = CVE_CONTEXT_PROMPT + retrieval.context
    return BuiltPrompt(prompt=prompt, query=query, retrieval=retrieval)


def build_prompt_from_report(report_path: Path) -> BuiltPrompt:
    """Threat-report path (Section 3, "Input": path to a threat report file)."""
    report_text = Path(report_path).read_text(encoding="utf-8")
    prompt = REPORT_PROMPT + report_text
    return BuiltPrompt(prompt=prompt, query=str(report_path))


def call_llm_and_save(
    built: BuiltPrompt,
    llm_client: LLMClient,
    db: Database,
) -> tuple[str, int]:
    """Calls the LLM, saves (prompt, raw response) to the DB, returns
    (raw_response, graph_row_id). Parsing into a graph dict is done by
    postprocess.parse_llm_json separately so callers can inspect malformed
    output before it is discarded."""
    raw_response = llm_client.complete(built.prompt)
    row_id = db.save_graph(built.query, built.prompt, raw_response, graph=None)
    return raw_response, row_id
