from enum import Enum
import sys
import types
from types import SimpleNamespace

import pytest

from crystalball.config import Settings
from crystalball.llm.factory import get_llm_client


@pytest.fixture(autouse=True)
def set_generation_defaults(monkeypatch):
    monkeypatch.setenv("LLM_MAX_OUTPUT_TOKENS", "4096")
    monkeypatch.setenv("LLM_REASONING_LEVEL", "low")


def test_openrouter_factory_uses_openai_sdk_compatible_endpoint(monkeypatch):
    captured = {}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            captured["init"] = kwargs

            def create(**completion_kwargs):
                captured["completion"] = completion_kwargs
                return SimpleNamespace(
                    model="openai/gpt-5.6-luna-20260709",
                    choices=[
                        SimpleNamespace(
                            message=SimpleNamespace(content="ok"),
                            finish_reason="stop",
                        )
                    ],
                    usage={
                        "prompt_tokens": 13,
                        "completion_tokens": 21,
                        "total_tokens": 34,
                        "completion_tokens_details": {"reasoning_tokens": 5},
                    },
                )

            self.chat = SimpleNamespace(
                completions=SimpleNamespace(
                    create=create
                )
            )

    openai_module = types.ModuleType("openai")
    openai_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", openai_module)

    client = get_llm_client(
        Settings(
            llm_backend="openrouter",
            openrouter_api_key="test-key",
            openrouter_model="openai/gpt-5.6-luna",
        )
    )

    assert client.complete("hello") == "ok"
    assert captured["init"] == {
        "api_key": "test-key",
        "base_url": "https://openrouter.ai/api/v1",
        "max_retries": 0,
    }
    assert captured["completion"]["model"] == "openai/gpt-5.6-luna"
    assert captured["completion"]["messages"] == [{"role": "user", "content": "hello"}]
    assert captured["completion"]["max_tokens"] == 4096
    assert captured["completion"]["reasoning_effort"] == "low"
    assert not {"temperature", "top_p", "seed"} & captured["completion"].keys()
    assert client.last_usage == {
        "prompt_tokens": 13,
        "completion_tokens": 21,
        "total_tokens": 34,
        "completion_tokens_details": {"reasoning_tokens": 5},
    }
    assert client.last_response_metadata == {
        "requested_model": "openai/gpt-5.6-luna",
        "actual_model": "openai/gpt-5.6-luna-20260709",
        "finish_reason": "stop",
        "finish_reasons": ["stop"],
        "usage": client.last_usage,
        "generation_config": {
            "max_output_tokens": 4096,
            "reasoning_effort": "low",
        },
    }


@pytest.mark.parametrize("output_limit", [512, 2048, 4096, 8192])
def test_openrouter_call_specific_generation_overrides(monkeypatch, output_limit):
    captured = {}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            def create(**completion_kwargs):
                captured["completion"] = completion_kwargs
                return SimpleNamespace(
                    choices=[SimpleNamespace(message=SimpleNamespace(content="ok"), finish_reason="stop")],
                    usage={},
                )

            self.chat = SimpleNamespace(completions=SimpleNamespace(create=create))

    openai_module = types.ModuleType("openai")
    openai_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", openai_module)

    client = get_llm_client(
        Settings(
            llm_backend="openrouter",
            openrouter_api_key="test-key",
            openrouter_model="openai/gpt-5.6-luna",
        )
    )
    assert client.complete("prompt", max_output_tokens=output_limit, reasoning_level="low") == "ok"
    assert captured["completion"]["max_tokens"] == output_limit
    assert captured["completion"]["reasoning_effort"] == "low"


@pytest.mark.parametrize(
    ("api_key", "model", "message"),
    [
        (None, "openai/gpt-5.6-luna", "OPENROUTER_API_KEY"),
        ("test-key", "", "OPENROUTER_MODEL"),
    ],
)
def test_openrouter_factory_fails_fast_when_configuration_missing(api_key, model, message):
    with pytest.raises(RuntimeError, match=message):
        get_llm_client(
            Settings(
                llm_backend="openrouter",
                openrouter_api_key=api_key,
                openrouter_model=model,
            )
        )


def test_gemini_factory_uses_google_genai_sdk(monkeypatch):
    captured = {}

    class FakeClient:
        def __init__(self, **kwargs):
            captured["init"] = kwargs

            def generate_content(**completion_kwargs):
                captured["completion"] = completion_kwargs
                return SimpleNamespace(
                    text="gemini result",
                    model_version="gemini-3.8-flash-001",
                    candidates=[SimpleNamespace(finish_reason=FakeFinishReason.MAX_TOKENS)],
                    usage_metadata=SimpleNamespace(
                        prompt_token_count=11,
                        candidates_token_count=17,
                        thoughts_token_count=9,
                        total_token_count=37,
                        cached_content_token_count=3,
                    ),
                )

            self.models = SimpleNamespace(
                generate_content=generate_content
            )

    google_module = types.ModuleType("google")
    class FakeFinishReason(Enum):
        MAX_TOKENS = 2

    google_module.genai = SimpleNamespace(
        Client=FakeClient,
        types=SimpleNamespace(
            HttpOptions=lambda **kwargs: SimpleNamespace(**kwargs),
            HttpRetryOptions=lambda **kwargs: SimpleNamespace(**kwargs),
            GenerateContentConfig=lambda **kwargs: SimpleNamespace(**kwargs),
            ThinkingConfig=lambda **kwargs: SimpleNamespace(**kwargs),
        ),
    )
    monkeypatch.setitem(sys.modules, "google", google_module)

    client = get_llm_client(Settings(llm_backend="gemini", gemini_api_key="gemini-key"))

    assert client.complete("prompt") == "gemini result"
    assert captured["init"] == {
        "api_key": "gemini-key",
        "http_options": SimpleNamespace(
            retry_options=SimpleNamespace(attempts=1)
        ),
    }
    assert captured["completion"]["model"] == "gemini-3.8-flash"
    assert captured["completion"]["contents"] == "prompt"
    assert captured["completion"]["config"].max_output_tokens == 4096
    assert captured["completion"]["config"].thinking_config.thinking_level == "low"
    assert not {"temperature", "top_p", "seed"} & captured["completion"].keys()
    assert client.last_usage == {
        "prompt_token_count": 11,
        "candidates_token_count": 17,
        "thoughts_token_count": 9,
        "total_token_count": 37,
        "cached_content_token_count": 3,
    }
    assert client.last_response_metadata == {
        "requested_model": "gemini-3.8-flash",
        "actual_model": "gemini-3.8-flash-001",
        "finish_reason": "MAX_TOKENS",
        "finish_reasons": ["MAX_TOKENS"],
        "usage": client.last_usage,
        "generation_config": {
            "max_output_tokens": 4096,
            "thinking_level": "low",
        },
    }


@pytest.mark.parametrize("output_limit", [512, 2048, 4096, 8192])
def test_gemini_call_specific_generation_overrides(monkeypatch, output_limit):
    captured = {}

    class FakeClient:
        def __init__(self, **kwargs):
            def generate_content(**completion_kwargs):
                captured["completion"] = completion_kwargs
                return SimpleNamespace(text="ok")

            self.models = SimpleNamespace(generate_content=generate_content)

    google_module = types.ModuleType("google")
    google_module.genai = SimpleNamespace(
        Client=FakeClient,
        types=SimpleNamespace(
            HttpOptions=lambda **kwargs: SimpleNamespace(**kwargs),
            HttpRetryOptions=lambda **kwargs: SimpleNamespace(**kwargs),
            GenerateContentConfig=lambda **kwargs: SimpleNamespace(**kwargs),
            ThinkingConfig=lambda **kwargs: SimpleNamespace(**kwargs),
        ),
    )
    monkeypatch.setitem(sys.modules, "google", google_module)

    client = get_llm_client(Settings(llm_backend="gemini", gemini_api_key="gemini-key"))
    assert client.complete("prompt", max_output_tokens=output_limit, reasoning_level="low") == "ok"
    assert captured["completion"]["config"].max_output_tokens == output_limit
    assert captured["completion"]["config"].thinking_config.thinking_level == "low"


@pytest.mark.parametrize(
    ("max_output_tokens", "reasoning_level"),
    [(0, "low"), (-1, "low"), (True, "low"), (512, "minimal"), (512, "invalid")],
)
def test_generation_overrides_are_validated_before_call(monkeypatch, max_output_tokens, reasoning_level):
    captured = {}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            def create(**completion_kwargs):
                captured["completion"] = completion_kwargs
                return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))])

            self.chat = SimpleNamespace(completions=SimpleNamespace(create=create))

    openai_module = types.ModuleType("openai")
    openai_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", openai_module)
    client = get_llm_client(
        Settings(
            llm_backend="openrouter",
            openrouter_api_key="test-key",
            openrouter_model="openai/gpt-5.6-luna",
        )
    )

    with pytest.raises(ValueError):
        client.complete(
            "prompt",
            max_output_tokens=max_output_tokens,
            reasoning_level=reasoning_level,
        )
    assert "completion" not in captured
