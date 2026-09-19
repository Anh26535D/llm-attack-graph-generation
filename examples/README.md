# Example: input -> output

A worked example of the full pipeline for the paper's Oculus Desktop /
Jetson TX1 / Raspberry Pi system (Section 5), so you can see the shape of
the input/output without running anything yourself first.

| File | What it is | How it was produced |
|---|---|---|
| `01_input_prompt.txt` | The retriever-augmented prompt | `uv run python scripts/build_prompt.py --products "Oculus Desktop" "Jetson TX1" "Raspberry Pi"` (after `setup_sample_data.py` + `ingest_cves.py`) |
| `02_sample_llm_response.txt` | An LLM's JSON answer to that prompt | **Hand-authored**, not a real ChatGPT/Gemini call — see note below |
| `03_output_graph.json` / `03_output_graph.png` | The parsed + rendered graph | `uv run python scripts/ingest_response.py --response 02_sample_llm_response.txt` |

**Important:** `02_sample_llm_response.txt` was written by hand (chaining
the 5 retrieved CVEs' pre/postconditions the way the paper's prompt asks
for), not sampled from a real LLM — this repo makes no real API calls by
default (see the top-level README). It exists only to demonstrate that
`ingest_response.py` correctly parses a graph out of a JSON answer and
renders it. For an actual GPT-4/Gemini/etc. result, paste
`01_input_prompt.txt` into a real chat UI (or set `LLM_BACKEND` in `.env`)
and run the same command on the real reply — expect a materially different,
model-specific graph.
