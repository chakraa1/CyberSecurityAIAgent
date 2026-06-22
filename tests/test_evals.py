"""Tests for the eval harness and loop engineering."""

from evals.evaluator import Evaluator, load_dataset
from evals.loop import ImprovementLoop


def test_dataset_loads():
    dataset = load_dataset()
    assert len(dataset) >= 5
    assert all("id" in c and "agent" in c for c in dataset)


def test_eval_suite_passes():
    report = Evaluator().run()
    # The bundled suite is designed to pass fully in offline mode.
    assert report.pass_rate == 100.0, [c.case_id for c in report.cases if not c.passed]


def test_loop_demo_improves_or_holds():
    history = ImprovementLoop().demo_threshold_sweep()
    h = history.to_dict()
    # Tuning the threshold from 50 -> 5 should not reduce the pass rate.
    assert h["best_pass_rate"] >= history.steps[0].pass_rate
    assert h["improvement"] >= 0
