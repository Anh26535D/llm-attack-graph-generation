# Live hybrid validation: Figures 7, 9, 10

Completed real Gemini API review with `gemini-3.8-flash`. All 14 edge instances passed strict response parsing, CVE/edge identity checks and evidence quotation verification. No generation API was called.

| Figure | Reviewed | Conditional | Unknown | API calls, all attempts | Provider total tokens | Before/After | Report |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 7 | 7/7 | 6 | 1 | 9 | 53,141 | [PNG](figure_07/comparison.png), [SVG](figure_07/comparison.svg) | [JSON](figure_07/validation_results.json) |
| 9 | 3/3 | 3 | 0 | 3 | 17,768 | [PNG](figure_09/comparison.png), [SVG](figure_09/comparison.svg) | [JSON](figure_09/validation_results.json) |
| 10 | 4/4 | 4 | 0 | 5 | 32,055 | [PNG](figure_10/comparison.png), [SVG](figure_10/comparison.svg) | [JSON](figure_10/validation_results.json) |

Total: **17 API calls**, including **3 retries** for truncated MAX_TOKENS responses. Provider total tokens, including thinking and failed attempts: **102,964**. The first successful Figure 7 review was cached during a one-request warmup and reused.

The configured output limit was 4096 with high reasoning. Only failed edges were retried with limit 8192: Figure 7 edge-0002 and edge-0005, Figure 10 edge-0001. `.env` was not changed. The successful cached reviews were not requested again. Each retry response records `request_overrides`; exact usage and served-model metadata remain in the reports/cache.

Initial failed graph runs are preserved under `attempts/`. [All API attempts](api_attempts.json) and [batch summary](summary.json) include warmup, initial requests and retries, so usage from failed requests is counted. Per-graph metrics describe their final invocation and can include cache hits; use the batch summary for total run cost/usage.

All original graph bytes/SHA-256, node sets, edge instances, offline baselines and layout hashes were verified unchanged. Supported/unsupported/contradicted final counts are zero. The LLM suggested unsupported for Figure 7 edge-0002; deterministic recheck retained unknown and recorded the disagreement. No independent gold labels are available, so Precision/Recall/F1 remain N/A. These results do not establish improved graph accuracy.
