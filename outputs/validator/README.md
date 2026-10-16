# Evidence-grounded C2 graph audits

**Live hybrid run:** [Figures 7, 9 and 10](hybrid_run_01/README.md) completed real Gemini review for all 14 edge instances, including evidence recheck. The batch records 17 API calls including three retries and 102,964 provider total tokens. [Full summary](hybrid_run_01/summary.json).

**Figure 2 scope check:** [offline diagnostic](figure_02_scope_check/validation_results.json) records 35 unmapped nodes and 36 unknown edges. Figure 2 is a SolarWinds threat-report graph outside the current CVE evidence adapter. No LLM API was called for this diagnostic; these unknown labels are not evidence that the graph is wrong.

The offline audits below were created from the saved original C2 graphs, using the pinned eight-CVE corpus and no environment observations. No generation or LLM review API was called for these offline runs. Original historical files remain unchanged; each run contains a byte-exact copy and original/canonical SHA-256 provenance.

| C2 input | Before/After PNG | Vector | Nodes mapped | Edges mapped | Conditional | Unknown | Unknown rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Figure 7 (Gemini) | [comparison](figure_07_offline/comparison.png) | [SVG](figure_07_offline/comparison.svg) | 8/8 | 7/7 | 6 | 1 | 14.29% |
| Figure 9 (OpenRouter) | [comparison](figure_09_offline/comparison.png) | [SVG](figure_09_offline/comparison.svg) | 8/8 | 3/3 | 3 | 0 | 0% |
| Figure 10 (OpenRouter V2) | [comparison](figure_10_offline/comparison.png) | [SVG](figure_10_offline/comparison.svg) | 8/8 | 4/4 | 4 | 0 | 0% |

Supported, unsupported and contradicted counts are zero in these observations. All candidates remain visible, retained fraction is 100%, and supported-only strict fraction is 0%. Strictly unconfirmed does not mean false. Different distributions across original graphs do not establish different accuracy.

Read [Figure 7 report](figure_07_offline/validation_results.json), [Figure 9 report](figure_09_offline/validation_results.json), [Figure 10 report](figure_10_offline/validation_results.json) for full claims, exact evidence, missing conditions and decisions. A/B/C metrics are in each `metrics.json`: A keeps unvalidated original candidates, B is offline checking, and C explicitly records `not_run_offline_fallback`. This is not a live hybrid experiment.

No independent gold is available: Precision/Recall/F1 and false removals/retentions are N/A (`null`). Blank annotation tables are supplied per run. Runtime measurements cover validation/review only, not generation or rendering. Fewer edges or fewer unknowns would not establish improved accuracy.

See [implementation and commands](../../docs/HYBRID_VALIDATOR.md) for independent backend selection, environment observations, cache/budget controls, tests, and the opt-in one-request smoke test.
