import json

from crystalball.extractors import HeuristicExtractor, LLMExtractor
from crystalball.llm.base import LLMClient

OVRREDIR_JSON = {
    "cveMetadata": {"cveId": "CVE-2020-1885", "state": "PUBLISHED"},
    "containers": {
        "cna": {
            "descriptions": [
                {
                    "lang": "en",
                    "value": (
                        "Writing to an unprivileged file from a privileged OVRRedir.exe "
                        "process in Oculus Desktop before 1.44.0.32849 on Windows allows "
                        "local users to write to arbitrary files and consequently gain "
                        "privileges via vectors involving a hard link to a log file."
                    ),
                }
            ],
            "affected": [
                {
                    "vendor": "Meta",
                    "product": "Oculus Desktop",
                    "platforms": ["Windows"],
                    "versions": [{"version": "1.44.0.32849", "lessThan": "1.44.0.32849"}],
                }
            ],
        }
    },
}


def test_heuristic_extractor_uses_structured_affected_field():
    extractor = HeuristicExtractor()
    description = OVRREDIR_JSON["containers"]["cna"]["descriptions"][0]["value"]
    props = extractor.extract(description, OVRREDIR_JSON)

    assert props.product_name == "Oculus Desktop"
    assert props.platform == "Windows"


def test_heuristic_extractor_falls_back_to_regex_without_affected():
    extractor = HeuristicExtractor()
    description = "A bug in RaspAP 2.5 on Raspberry Pi OS allows remote code execution."
    props = extractor.extract(description, {})

    assert props.platform == "Raspberry Pi OS"


class FakeLLMClient(LLMClient):
    name = "fake"

    def __init__(self, response: str) -> None:
        self.response = response

    def complete(self, prompt: str) -> str:
        return self.response


def test_llm_extractor_parses_fenced_json():
    payload = {
        "ProductInfo": {
            "ProductName": "piSignage",
            "Version": {"VersionNumber": "2.6.4", "Qualifier": "<"},
        },
        "Platform": "Raspberry Pi OS",
        "ProblemType": "Path Traversal",
    }
    raw = "Sure, here you go:\n```json\n" + json.dumps(payload) + "\n```"
    extractor = LLMExtractor(FakeLLMClient(raw))

    props = extractor.extract("irrelevant description", {})

    assert props.product_name == "piSignage"
    assert props.version.version_number == "2.6.4"
    assert props.version.qualifier == "<"
    assert props.platform == "Raspberry Pi OS"
    assert props.problem_type == "Path Traversal"
