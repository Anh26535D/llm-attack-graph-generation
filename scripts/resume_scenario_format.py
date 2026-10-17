"""Explicit format-only recovery in a new directory; preserve strict-run failure.

The amendment accepts one whole-response Markdown JSON fence, uniformly for
every stage. It never repairs JSON, chooses duplicate keys or changes claims.
All received requests are copied with their journals and reused. Started/error
requests cannot be retried by this tool.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from crystalball.config import Settings
from crystalball.generation_debate import strict_object
from crystalball.generation_debate_runner import Journal, read, save
import crystalball.scenario_debate as runner


def unwrap(raw: str) -> tuple[str, bool]:
    match = re.fullmatch(r"\s*```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n```\s*", raw)
    if not match:
        return raw, False
    candidate = match.group(1)
    strict_object(candidate)  # Do not salvage truncation, prose or duplicate keys.
    return candidate, True


def prepare_recovery(source: Path, destination: Path, settings: Settings):
    source, destination = source.resolve(), destination.resolve()
    if source == destination or source in destination.parents or destination in source.parents:
        raise ValueError("Recovery must be a separate sibling run directory")
    runner.verify(source, settings)
    if (source / ".execute.lock").exists():
        raise ValueError("Source still has an execution lock; inspect it before recovery")
    calls = list(source.glob("runs/r*/calls/*.json"))
    for path in calls:
        record = read(path)
        if record["status"] != "received" or record.get("output_truncated"):
            raise ValueError("Only received, nontruncated requests can be recovered")
        raw_path = path.with_suffix(".response.txt")
        if hashlib.sha256(raw_path.read_bytes()).hexdigest() != record["response_sha256"]:
            raise ValueError("Source raw hash mismatch")
    destination.mkdir(parents=True, exist_ok=False)
    names = ["manifest.json", "frozen_hashes.json", "scenario.json", "reference.synthetic.json",
             "task.txt", "draft_prompt.txt", "raw_scenario.txt", "CONTINUATION.json"]
    inputs = {}
    for name in names:
        path = source / name
        if path.exists():
            shutil.copyfile(path, destination / name)
            inputs[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    if (source / "code_snapshot").exists():
        shutil.copytree(source / "code_snapshot", destination / "code_snapshot")
    for path in source.glob("runs/r*/calls/*"):
        if path.is_file():
            relative = path.relative_to(source)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            inputs[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    save(destination / "FORMAT_RECOVERY.json", {"source_run": str(source),
        "original_protocol_result": "strict-format failure; retained in original directory",
        "amendment": "Accept exactly one whole-response Markdown JSON fence at every stage, then use unchanged strict JSON/schema/quote/decision checks.",
        "semantic_edits": False, "requests_reused": len(calls),
        "requests_retried": 0, "remaining_budget": read(source / "manifest.json")["max_api_calls_total"] - len(calls),
        "copied_input_sha256": inputs,
        "wrapper_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})


class FormatJournal(Journal):
    def complete(self, stage, role, prompt):
        raw = super().complete(stage, role, prompt)
        normalized, changed = unwrap(raw)
        if changed:
            folder = self.folder / "format_normalization"
            folder.mkdir(exist_ok=True)
            (folder / f"{stage}.json.txt").write_bytes(normalized.encode("utf-8"))
            save(folder / f"{stage}.audit.json", {"rule": "whole_response_markdown_fence_only",
                "raw_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "normalized_sha256": hashlib.sha256(normalized.encode()).hexdigest(),
                "json_content_changed": False})
        return normalized


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    prepare_recovery(args.source, args.out, Settings())
    runner.Journal = FormatJournal
    runner.execute(args.out, Settings())
    source_hashes = read(args.out / "FORMAT_RECOVERY.json")["copied_input_sha256"]
    assert all(hashlib.sha256((args.source / name).read_bytes()).hexdigest() == expected
               for name, expected in source_hashes.items())
    print("Recovery completed; original run artifacts unchanged.")


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    main()
