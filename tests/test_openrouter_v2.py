import importlib.util
import json
from pathlib import Path
import sys
import types
from types import SimpleNamespace

import pytest

from crystalball.config import Settings
from crystalball.llm.factory import get_llm_client


@pytest.fixture
def fake_sdk(monkeypatch):
    calls = {"init": [], "completion": []}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            calls["init"].append(kwargs)

            def create(**request):
                calls["completion"].append(request)
                return SimpleNamespace(
                    model=request["model"], provider="Baidu",
                    choices=[SimpleNamespace(message=SimpleNamespace(content='{"nodes":[],"edges":[]}'),
                                             finish_reason="stop")],
                    usage={"prompt_tokens": 20, "completion_tokens": 40},
                )

            self.chat = SimpleNamespace(completions=SimpleNamespace(create=create))

    module = types.ModuleType("openai")
    module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", module)
    monkeypatch.setenv("LLM_REASONING_LEVEL", "low")
    return calls


def v2_settings(**overrides):
    values = {
        "llm_backend": "openrouter_v2",
        "openrouter_api_key": "v1-key",
        "openrouter_model": "v1-model",
        "openrouter_api_key_v2": "v2-key",
        "openrouter_model_v2": "deepseek/deepseek-v4.1-flash",
        "openrouter_provider_config_v2": '{"only":["baidu/fp8"],"allow_fallbacks":false}',
        "llm_max_output_tokens": 16384,
    }
    return Settings(**(values | overrides))


def test_v2_routes_with_its_own_key_model_and_high_reasoning(fake_sdk):
    client = get_llm_client(v2_settings())
    assert client.complete("graph prompt") == '{"nodes":[],"edges":[]}'
    assert client.name == "openrouter_v2"
    assert fake_sdk["init"][0]["api_key"] == "v2-key"
    request = fake_sdk["completion"][0]
    assert request["model"] == "deepseek/deepseek-v4.1-flash"
    assert request["max_tokens"] == 16384
    assert request["extra_body"] == {
        "provider": {"only": ["baidu/fp8"], "allow_fallbacks": False},
        "reasoning": {"effort": "high"},
    }
    assert "reasoning_effort" not in request
    assert client.last_response_metadata["generation_config"]["provider"] == request["extra_body"]["provider"]
    assert client.last_response_metadata["actual_provider"] == "Baidu"
    assert "v2-key" not in json.dumps(client.last_response_metadata)


def test_v1_does_not_inherit_v2_routing(fake_sdk):
    settings = v2_settings(llm_backend="openrouter")
    client = get_llm_client(settings)
    client.complete("prompt")
    assert fake_sdk["init"][0]["api_key"] == "v1-key"
    assert fake_sdk["completion"][0]["model"] == "v1-model"
    assert fake_sdk["completion"][0]["reasoning_effort"] == "low"
    assert "extra_body" not in fake_sdk["completion"][0]


@pytest.mark.parametrize("config", ["", "not-json", "[]", "null", '"baidu/fp8"'])
def test_bad_v2_provider_json_fails_before_creating_client(fake_sdk, config):
    with pytest.raises(ValueError, match="OPENROUTER_PROVIDER_CONFIG_V2"):
        get_llm_client(v2_settings(openrouter_provider_config_v2=config))
    assert fake_sdk["init"] == []


@pytest.mark.parametrize(("overrides", "variable"), [
    ({"openrouter_api_key_v2": None}, "OPENROUTER_API_KEY_V2"),
    ({"openrouter_model_v2": "  "}, "OPENROUTER_MODEL_V2"),
])
def test_v2_missing_credentials_do_not_use_v1(fake_sdk, overrides, variable):
    with pytest.raises(RuntimeError, match=variable):
        get_llm_client(v2_settings(**overrides))
    assert fake_sdk["init"] == []


def test_settings_read_the_three_v2_environment_variables(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY_V2", "env-v2-key")
    monkeypatch.setenv("OPENROUTER_MODEL_V2", "env-v2-model")
    monkeypatch.setenv("OPENROUTER_PROVIDER_CONFIG_V2", '{"only":["another/provider"]}')
    settings = Settings()
    assert settings.openrouter_api_key_v2 == "env-v2-key"
    assert settings.openrouter_model_v2 == "env-v2-model"
    assert json.loads(settings.openrouter_provider_config_v2) == {"only": ["another/provider"]}
    assert "env-v2-key" not in repr(settings)


@pytest.mark.parametrize(("backend", "reasoning"), [("openrouter_v2", "high"), ("openrouter", "medium")])
def test_demo_check_selects_reasoning_and_never_calls_api(fake_sdk, monkeypatch, tmp_path, backend, reasoning):
    import dotenv

    script = Path(__file__).resolve().parents[1] / "scripts/demo_online.py"
    spec = importlib.util.spec_from_file_location("demo_online_v2_test", script)
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    monkeypatch.setattr(demo, "ROOT", tmp_path)
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *args, **kwargs: None)
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "data/reproduction/solarwinds_full_appendix_c1.txt"
    source.parent.mkdir(parents=True)
    source.write_text("Original instruction\n\nPublic report paragraph.", encoding="utf-8")
    monkeypatch.setenv("OPENROUTER_API_KEY", "v1-key")
    monkeypatch.setenv("OPENROUTER_MODEL", "v1-model")
    monkeypatch.setenv("OPENROUTER_API_KEY_V2", "v2-key")
    monkeypatch.setenv("OPENROUTER_MODEL_V2", "v2-model")
    monkeypatch.setenv("OPENROUTER_PROVIDER_CONFIG_V2", '{"only":["baidu/fp8"],"allow_fallbacks":false}')
    monkeypatch.setattr(sys, "argv", [str(script), "--backend", backend, "--check", "--no-open"])
    assert demo.main() == 0
    assert fake_sdk["completion"] == []
    assert fake_sdk["init"][0]["api_key"] == ("v2-key" if backend == "openrouter_v2" else "v1-key")
    metadata_path = next((tmp_path / "outputs/demo_online").glob("*/metadata.json"))
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["backend"] == backend
    assert metadata["reasoning"] == reasoning
    assert metadata["status"] == "prepared"
    if backend == "openrouter_v2":
        assert metadata["provider_config"] == {"only": ["baidu/fp8"], "allow_fallbacks": False}
