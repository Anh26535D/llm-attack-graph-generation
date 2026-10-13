import json
from pathlib import Path
import shutil
import importlib.util
import sys
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest

from crystalball.paper_cases import CASES, load_prompt, prepare_references
from crystalball.paper_graph import render_paper_graph, t0_overview
from crystalball import paper_runner
from crystalball.postprocess import AttackGraph

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def paper_root(tmp_path, monkeypatch):
    shutil.copytree(REPO / "data/reproduction", tmp_path / "data/reproduction")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test")
    monkeypatch.setenv("OPENROUTER_MODEL", "luna-test")
    monkeypatch.setenv("OPENROUTER_MODEL_V2", "deepseek-test")
    return tmp_path


def fake_clients(monkeypatch, calls):
    def make(settings):
        model = {"gemini": settings.gemini_model, "openrouter": settings.openrouter_model, "openrouter_v2": settings.openrouter_model_v2}[settings.llm_backend]
        def complete(prompt, **kwargs):
            calls.append((settings.llm_backend, prompt, kwargs))
            return json.dumps({"nodes": [{"id": "a", "label": "Initial access"}, {"id": "b", "label": "Local execution"}], "edges": [{"from": "a", "to": "b", "label": "Enables code execution"}]})
        return SimpleNamespace(model=model, complete=complete, last_usage={}, last_response_metadata={})
    monkeypatch.setattr(paper_runner, "get_llm_client", make)


def test_nine_figures_preserve_same_comparison_prompts():
    assert [case.figure for case in CASES] == [2, 6, 7, 8, 9, 10, 11, 12, 13]
    assert {case.backend for case in CASES} == {"gemini", "openrouter", "openrouter_v2"}
    for condition in ("C2", "T0"):
        assert len({load_prompt(REPO, case) for case in CASES if case.condition == condition}) == 1
    assert {case.condition for case in CASES} == {"C0", "C2", "T0", "T1", "T2"}


def test_runner_sends_nine_requests_and_resume_only_renders(paper_root, monkeypatch):
    calls = []
    fake_clients(monkeypatch, calls)
    assert paper_runner.main(["--run-id", "nine", "--no-open"], root=paper_root) == 0
    assert len(calls) == 9
    assert all(call[2]["reasoning_level"] == "high" for call in calls)
    out = paper_root / "outputs/paper_nine/nine"
    assert (out / "index.html").exists()
    assert len(list(out.glob('figures/*/comparison.html'))) == 9
    assert len(list(out.glob('figures/*/graph.png'))) == 9
    assert paper_runner.main(["--resume", str(out), "--render-only", "--no-open"], root=paper_root) == 0
    assert len(calls) == 9


def test_preflight_has_nine_prompts_but_no_generation(paper_root, monkeypatch):
    calls = []
    fake_clients(monkeypatch, calls)
    assert paper_runner.main(["--run-id", "check", "--check", "--no-open"], root=paper_root) == 0
    assert calls == []
    out = paper_root / "outputs/paper_nine/check"
    assert len(list(out.glob('figures/*/prompt.txt'))) == 9
    assert not list(out.glob('figures/*/response.txt'))


def test_preflight_uses_shipped_references_without_external_pdf(paper_root, monkeypatch):
    bundled = paper_root / 'outputs/paper_nine/paper9_20261013_original/references'
    shutil.copytree(REPO / 'outputs/paper_nine/paper9_20261013_original/references', bundled)
    calls = []
    fake_clients(monkeypatch, calls)
    assert paper_runner.main(['--run-id', 'clone_check', '--check', '--no-open'], root=paper_root) == 0
    actual = paper_root / 'outputs/paper_nine/clone_check/references'
    assert len(list(actual.glob('figure_*.png'))) == 9
    assert (actual / 'references.json').read_bytes() == (bundled / 'references.json').read_bytes()
    for case in CASES:
        name = f'figure_{case.figure:02d}.png'
        assert (actual / name).read_bytes() == (bundled / name).read_bytes()
    assert calls == []


def test_corrupted_shipped_reference_is_rejected_before_copy(paper_root):
    bundled = paper_root / 'outputs/paper_nine/paper9_20261013_original/references'
    shutil.copytree(REPO / 'outputs/paper_nine/paper9_20261013_original/references', bundled)
    (bundled / 'figure_07.png').write_bytes(b'corrupted')
    destination = paper_root / 'new_references'
    with pytest.raises(ValueError, match='Bundled reference hash mismatch'):
        prepare_references(paper_root, destination)
    assert not destination.exists()


def test_frozen_prompt_tampering_prevents_api(paper_root, monkeypatch):
    calls = []
    fake_clients(monkeypatch, calls)
    paper_runner.main(["--run-id", "check", "--check", "--no-open"], root=paper_root)
    out = paper_root / "outputs/paper_nine/check"
    next(out.glob('figures/*/prompt.txt')).write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        paper_runner.main(["--resume", str(out), "--no-open"], root=paper_root)
    assert calls == []


def test_renderer_keeps_parallel_edges_and_complete_labels(tmp_path):
    graph = AttackGraph(nodes=[{"id": "a", "name": "Oculus Browser HTML injection"}, {"id": "b", "label": "OVRRedir.exe privilege escalation"}],
                        edges=[{"from": "a", "to": "b", "label": "Enables local execution"}, {"from": "a", "to": "b", "label": "Requires the same Windows host"}])
    before = json.dumps(graph.to_dict(), sort_keys=True)
    result = render_paper_graph(graph, tmp_path, title="Figure 7")
    tree = ET.fromstring((tmp_path / 'graph.svg').read_text(encoding='utf-8'))
    ns = {'s': 'http://www.w3.org/2000/svg'}
    assert len(tree.findall('.//s:circle', ns)) == 2
    assert len(tree.findall('.//s:g[@class="edge"]', ns)) == 2
    assert result['node_labels'][0] == 'Oculus Browser HTML injection'
    assert result['edge_labels'] == [edge['label'] for edge in graph.edges]
    assert result['label_collisions'] == 0
    assert json.dumps(graph.to_dict(), sort_keys=True) == before


def test_bad_endpoints_are_not_silently_deleted(tmp_path):
    graph = AttackGraph(nodes=[{'id': 'a', 'label': 'A'}], edges=[{'from': 'a', 'to': 'missing', 'label': 'invalid'}])
    with pytest.raises(ValueError, match='Missing edge endpoint'):
        render_paper_graph(graph, tmp_path, title='Bad')


@pytest.mark.parametrize('figure', [case.figure for case in CASES])
def test_online_demo_routes_every_paper_figure(paper_root, monkeypatch, figure):
    calls = []
    fake_clients(monkeypatch, calls)
    spec = importlib.util.spec_from_file_location('paper_demo_route', REPO / 'scripts/demo_online.py')
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    monkeypatch.setattr(demo, 'ROOT', paper_root)
    monkeypatch.setattr(sys, 'argv', ['demo_online.py', '--figure', str(figure), '--check', '--no-open'])
    assert demo.main() == 0
    manifest = json.loads(next((paper_root / 'outputs/paper_nine').glob('*/manifest.json')).read_text(encoding='utf-8'))
    assert [entry['figure'] for entry in manifest['entries']] == [figure]
    assert calls == []


def test_reusing_a_matching_run_skips_the_paid_request(paper_root, monkeypatch):
    calls = []
    fake_clients(monkeypatch, calls)
    paper_runner.main(['--run-id', 'one', '--figures', '2', '--no-open'], root=paper_root)
    one = paper_root / 'outputs/paper_nine/one'
    assert len(calls) == 1
    assert paper_runner.main(['--run-id', 'combined', '--reuse-run', str(one), '--no-open'], root=paper_root) == 0
    assert len(calls) == 9  # the first response was reused, not generated twice


def test_saved_response_tampering_is_reported_without_regeneration(paper_root, monkeypatch):
    calls = []
    fake_clients(monkeypatch, calls)
    paper_runner.main(['--run-id', 'one', '--figures', '2', '--no-open'], root=paper_root)
    out = paper_root / 'outputs/paper_nine/one'
    next(out.glob('figures/*/response.txt')).write_text('{"nodes":[],"edges":[]}', encoding='utf-8')
    assert paper_runner.main(['--resume', str(out), '--render-only', '--no-open'], root=paper_root) == 1
    assert len(calls) == 1


def test_api_failure_does_not_trigger_more_calls_on_that_backend(paper_root, monkeypatch):
    calls = []
    def make(settings):
        model = {'gemini': settings.gemini_model, 'openrouter': settings.openrouter_model, 'openrouter_v2': settings.openrouter_model_v2}[settings.llm_backend]
        def fail(*args, **kwargs):
            calls.append(settings.llm_backend)
            raise RuntimeError('API unavailable')
        return SimpleNamespace(model=model, complete=fail, last_usage={}, last_response_metadata={})
    monkeypatch.setattr(paper_runner, 'get_llm_client', make)
    assert paper_runner.main(['--run-id', 'errors', '--no-open'], root=paper_root) == 1
    assert calls == ['gemini', 'openrouter', 'openrouter_v2']


def test_overview_is_a_traceable_projection_not_a_fake_model_response():
    graph = AttackGraph(nodes=[{'id': 'a', 'label': 'Attacker'}, {'id': 'p', 'label': 'Trust Authentication Misconfiguration'},
                              {'id': 'q', 'label': 'Unauthorized PostgreSQL Access'}, {'id': 'w', 'label': 'WordPress'},
                              {'id': 'r', 'label': 'Remote Code Execution Vulnerability'}],
                        edges=[{'from': 'a', 'to': 'p', 'label': 'Finds server'}, {'from': 'p', 'to': 'q', 'label': 'Allows unauthenticated access'},
                               {'from': 'w', 'to': 'r', 'label': 'May expose RCE'}])
    before = json.dumps(graph.to_dict(), sort_keys=True)
    overview, record = t0_overview(graph)
    assert len(overview.nodes) == 4 and len(overview.edges) == 2
    assert record['omitted_context_nodes'] == ['a']
    assert record['new_relations_inferred'] is False
    assert 'Liferay' not in next(node['label'] for node in overview.nodes if node['id'] == 'applications')
    assert {idx for edge in overview.edges for idx in edge['source_edges']} == {1, 2}
    assert json.dumps(graph.to_dict(), sort_keys=True) == before
