"""Evaluation harness + loop-engineering for the agent system.

Inspired by lightweight, assertion-driven eval suites (e.g. the public
``kingsidharth/evals_1`` project): define a dataset of cases with expected
properties, run the system, score with deterministic assertions (plus optional
LLM-as-judge), and emit a report. This makes agent quality measurable and
regression-testable — essential for a financial-services deployment.
"""

from .metrics import CaseResult, EvalReport, assertion_checks
from .evaluator import Evaluator, load_dataset
from .loop import ImprovementLoop

__all__ = [
    "CaseResult",
    "EvalReport",
    "assertion_checks",
    "Evaluator",
    "load_dataset",
    "ImprovementLoop",
]
