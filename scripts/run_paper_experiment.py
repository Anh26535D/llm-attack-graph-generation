"""Run just the nine illustrated paper cases with three substitute models."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from crystalball.paper_runner import main, safe_error

if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[ERROR] {safe_error(exc)}", file=sys.stderr)
        raise SystemExit(1)
