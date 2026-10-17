# Three reviewers on the same ten frozen C2 graphs

Registered before the new DeepSeek and GPT requests. Reuse the ten original Gemini generations from `c2_10_20261016_01` (58 edge instances). Reuse completed Gemini reviews from `c2_10_20261016_high_9999_01`; no new generation or Gemini requests.

DeepSeek uses `openrouter_v2`; GPT uses `openrouter`. Model identities and provider settings are frozen in each run manifest. Do not edit the user's selected .env backend when switching between reviewers.

Keep original graph bytes, official evidence, offline baseline, semantic review prompt, selected statuses (conditional, unknown) and graph layout identical. Primary profile: high reasoning, 9999 output tokens, matching existing Gemini. At most one technical retry per failed edge, at 16384 tokens; reuse successful primary-profile cache entries. Keep first-pass failures in the reported statistics. Never retry to obtain a preferred semantic label.

Honor the current user's limit of 10 total requests per round for each new reviewer, including retries. The historical Gemini manifest allowed 20 per round, but actually used at most 10 per round including retries. Report this budget difference and any exhausted retry budget. The same reasoning name and token limit do not imply identical compute across providers.

Compare first-pass and final parse/identity/quote-check success, raw verified LLM status suggestions, final gated statuses, accepted offline-to-hybrid changes, disagreements, API requests and provider token usage. Pairwise suggestion agreement uses only the common verified edge outputs. Keep invalid output separate from semantic unknown. No independent gold labels exist: do not report accuracy, precision, recall, F1 or a model accuracy ranking.
