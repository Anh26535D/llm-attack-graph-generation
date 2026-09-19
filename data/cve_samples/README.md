# Sample CVE records

Run `uv run python scripts/setup_sample_data.py` to materialize these files
(they are generated, not committed to git — see `scripts/setup_sample_data.py`
for the source data and rationale).

These 8 records reproduce the exact "system consisting of Oculus, Jetson TX1
and Raspberry Pi" example from Section 5 / Appendix A of the paper. Each
JSON file follows the real [CVE Record Format v5](https://github.com/CVEProject/cvelistV5)
schema (`cveMetadata` + `containers.cna`) so the ingestion pipeline
(`crystalball.preprocess`) exercises the same code path it would against a
real download from the CVE GitHub repository.

**Provenance note:** the vulnerability *descriptions* are copied verbatim
from Appendix A of the paper (which the authors themselves sourced from
public CVE/NVD records). Two CVE IDs are confirmed from the paper itself
(`CVE-2020-25299` for the piSignage path traversal, and `CVE-2020-1885` for
the OVRRedir.exe issue shown in Figure 1). The remaining IDs
(`CVE-2024-90001`..`90005`) are **placeholders** assigned for this
reproduction only, since the paper's text doesn't state them explicitly —
do not treat them as authoritative MITRE identifiers. The `affected`
structured fields (vendor/product/platform/version) are reconstructed
best-effort from the description text to let the heuristic extractor be
exercised realistically; swap `EXTRACTOR_BACKEND=llm` to have an LLM derive
them from the free text instead, as the paper does.

To try this against *real, current* CVE data instead: download any record
from https://github.com/CVEProject/cvelistV5 and drop it in this directory
(or point `scripts/ingest_cves.py --input` at your own folder) — the schema
is identical.
