from pathlib import Path

from airgap_agent.agent.eval import load_eval_cases, run_eval_cases
from airgap_agent.config import AppConfig


def test_eval_security_fixtures() -> None:
    root = Path(__file__).resolve().parents[1]
    cases = load_eval_cases(root / "eval" / "fixtures")
    results = run_eval_cases(cases, config=AppConfig())
    assert all(r.ok for r in results), [r for r in results if not r.ok]
