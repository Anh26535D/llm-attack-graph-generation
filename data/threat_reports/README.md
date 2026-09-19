# Sample threat reports

Run `uv run python scripts/setup_sample_data.py` to materialize these files
(they are generated, not committed — see `scripts/setup_sample_data.py`).

Three excerpts quoted in the paper's Appendix B/C, condensed from the
original public write-ups:

- `solarwinds_full.txt` / `solarwinds_evasion.txt` — FireEye/Mandiant's
  report on the SolarWinds Orion supply-chain compromise (UNC2452 / SUNBURST).
- `kubernetes_cluster_hacked.txt` — Microsoft's write-up on Kubernetes
  clusters compromised via misconfigured PostgreSQL and vulnerable
  container images.

To build a graph from a different report, save any threat-intel write-up as
a `.txt` file anywhere and pass it to `scripts/build_prompt.py --report`.
