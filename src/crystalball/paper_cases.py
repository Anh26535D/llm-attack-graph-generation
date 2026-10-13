"""The nine published attack graphs, represented by five frozen prompts."""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path


@dataclass(frozen=True)
class PaperCase:
    figure: int
    condition: str
    backend: str
    original_model: str
    title: str
    source: str | None
    image: str
    page: int


CASES = (
    PaperCase(2, "T1", "gemini", "GPT-4", "SolarWinds full report", "solarwinds_full_appendix_c1.txt", "Im2.png", 3),
    PaperCase(6, "C0", "gemini", "ChatGPT", "No-context baseline", None, "Im6.png", 6),
    PaperCase(7, "C2", "gemini", "GPT-4", "Eight CVE descriptions", "appendix_a_context.txt", "Im7.png", 6),
    PaperCase(8, "T2", "gemini", "GPT-4", "SolarWinds evasion", "solarwinds_evasion_appendix_c2.txt", "Im8.png", 7),
    PaperCase(9, "C2", "openrouter", "GPT-3.5", "Eight CVE descriptions", "appendix_a_context.txt", "Im9.png", 7),
    PaperCase(10, "C2", "openrouter_v2", "Bard", "Eight CVE descriptions", "appendix_a_context.txt", "Im10.png", 7),
    PaperCase(11, "T0", "gemini", "GPT-4", "PostgreSQL and container paths", "kubernetes_appendix_b.txt", "Im11.png", 8),
    PaperCase(12, "T0", "openrouter", "GPT-3.5", "PostgreSQL and container paths", "kubernetes_appendix_b.txt", "Im12.png", 8),
    PaperCase(13, "T0", "openrouter_v2", "Bard", "PostgreSQL and container paths", "kubernetes_appendix_b.txt", "Im13.png", 8),
)
BY_FIGURE = {case.figure: case for case in CASES}
BACKENDS = ("gemini", "openrouter", "openrouter_v2")
BASELINE = "Create an attack graph in json format using only nodes and edges as keys for a system comprising of Raspberry Pi, Oculus Desktop, NVIDIA Jetson Nano.\n\n"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_prompt(root: Path, case: PaperCase) -> str:
    if case.source is None:
        return BASELINE
    folder = root / "data/reproduction"
    payload = (folder / case.source).read_bytes()
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if digest(payload) != manifest["files"][case.source]["sha256"]:
        raise ValueError(f"Source hash mismatch: {case.source}")
    return payload.decode("utf-8")


def extract_references(root: Path, destination: Path, pdf: Path | None = None) -> dict:
    """Extract the paper's embedded images, without resampling/cropping them."""
    from pypdf import PdfReader

    source = pdf or root.parent / "Using Retriever Augmented Large Language Models for Attack Graph Generation.pdf"
    manifest = json.loads((root / "data/reproduction/manifest.json").read_text(encoding="utf-8"))
    pdf_hash = digest(source.read_bytes())
    if pdf_hash != manifest["source_pdf"]["sha256"]:
        raise ValueError("PDF differs from the pinned paper; verify its image mapping first.")
    reader = PdfReader(source)
    images = {}
    for case in CASES:
        image = next((item for item in reader.pages[case.page - 1].images if item.name == case.image), None)
        if image is None:
            raise ValueError(f"Missing original Figure {case.figure}: {case.image}")
        images[case.figure] = image
    destination.mkdir(parents=True, exist_ok=True)
    records = {}
    for figure, image in images.items():
        target = destination / f"figure_{figure:02d}.png"
        target.write_bytes(image.data)
        records[str(figure)] = {"file": target.name, "sha256": digest(image.data), "size": list(image.image.size)}
    record = {"source_pdf_sha256": pdf_hash, "images": records}
    (destination / "references.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def prepare_references(root: Path, destination: Path, pdf: Path | None = None) -> dict | None:
    """Use the pinned PDF or verified reference images shipped with the results."""
    source = pdf or root.parent / "Using Retriever Augmented Large Language Models for Attack Graph Generation.pdf"
    if source.is_file():
        return extract_references(root, destination, source)
    if pdf is not None:
        raise FileNotFoundError(f"Reference PDF not found: {pdf}")
    bundled = root / "outputs/paper_nine/paper9_20261013_original/references"
    reference_manifest = bundled / "references.json"
    if not reference_manifest.is_file():
        return None
    record = json.loads(reference_manifest.read_text(encoding="utf-8"))
    pinned = json.loads((root / "data/reproduction/manifest.json").read_text(encoding="utf-8"))
    if record["source_pdf_sha256"] != pinned["source_pdf"]["sha256"]:
        raise ValueError("Bundled references have a different source PDF hash")
    images = {}
    for case in CASES:
        filename = f"figure_{case.figure:02d}.png"
        expected = record["images"][str(case.figure)]
        payload = (bundled / filename).read_bytes()
        if expected["file"] != filename or digest(payload) != expected["sha256"]:
            raise ValueError(f"Bundled reference hash mismatch: Figure {case.figure}")
        images[filename] = payload
    destination.mkdir(parents=True, exist_ok=True)
    for filename, payload in images.items():
        (destination / filename).write_bytes(payload)
    (destination / "references.json").write_bytes(reference_manifest.read_bytes())
    return record
