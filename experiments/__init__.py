import sys
from pathlib import Path

# Make the CrystalBall package importable without installing it.
_SRC = str(Path(__file__).resolve().parents[1] / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
