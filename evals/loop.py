"""Loop engineering: iteratively measure and improve agent quality.

"Loop engineering" here means closing the feedback loop between *evaluation* and
*configuration*: we repeatedly run the eval suite, inspect failures, try a
candidate change, keep it only if the score improves, and record the trajectory.
This yields concrete insight into how (and whether) the agent is improving.

The bundled demonstration sweeps the Log Monitor's brute-force detection
threshold and shows recall improving as the threshold is tuned — a transparent,
deterministic example that runs fully offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from config import get_logger
from evals.evaluator import Evaluator
from evals.metrics import EvalReport
from tools.log_tools import get_brute_force_threshold, set_brute_force_threshold

logger = get_logger(__name__)


@dataclass
class LoopStep:
    iteration: int
    config: Dict[str, Any]
    pass_rate: float
    passed: int
    total: int
    accepted: bool
    failing_cases: List[str] = field(default_factory=list)


@dataclass
class LoopHistory:
    steps: List[LoopStep] = field(default_factory=list)
    best_config: Dict[str, Any] = field(default_factory=dict)
    best_pass_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "best_config": self.best_config,
            "best_pass_rate": self.best_pass_rate,
            "improvement": round(
                (self.steps[-1].pass_rate - self.steps[0].pass_rate), 1
            ) if len(self.steps) >= 1 else 0.0,
            "steps": [s.__dict__ for s in self.steps],
        }


class ImprovementLoop:
    """Runs an eval/measure/adjust loop and records the trajectory."""

    def __init__(self, evaluator: Optional[Evaluator] = None) -> None:
        self._evaluator = evaluator or Evaluator()

    def _score(self) -> EvalReport:
        return self._evaluator.run()

    def run(
        self,
        candidate_configs: List[Dict[str, Any]],
        apply_config: Callable[[Dict[str, Any]], None],
    ) -> LoopHistory:
        """Greedy hill-climb over a list of candidate configs.

        ``apply_config`` mutates global/agent state to reflect a candidate; the
        loop keeps the best-scoring configuration.
        """
        history = LoopHistory()
        for i, cfg in enumerate(candidate_configs):
            apply_config(cfg)
            report = self._score()
            accepted = report.pass_rate > history.best_pass_rate
            if accepted:
                history.best_pass_rate = report.pass_rate
                history.best_config = cfg
            failing = [c.case_id for c in report.cases if not c.passed]
            history.steps.append(
                LoopStep(
                    iteration=i,
                    config=cfg,
                    pass_rate=report.pass_rate,
                    passed=report.passed,
                    total=report.total,
                    accepted=accepted,
                    failing_cases=failing,
                )
            )
            logger.info("[loop] iter=%d config=%s pass_rate=%.1f%% accepted=%s",
                        i, cfg, report.pass_rate, accepted)
        # Re-apply the best config so the system is left in its best state.
        if history.best_config:
            apply_config(history.best_config)
        return history

    # ---- bundled demonstration ------------------------------------------
    def demo_threshold_sweep(self) -> LoopHistory:
        """Sweep the brute-force threshold (worst -> best) and record gains."""
        original = get_brute_force_threshold()
        try:
            configs = [{"brute_force_threshold": t} for t in (50, 20, 10, 5)]
            history = self.run(
                configs,
                lambda cfg: set_brute_force_threshold(cfg["brute_force_threshold"]),
            )
        finally:
            # demo_threshold_sweep ends on the best config; only restore if the
            # loop somehow found nothing.
            if not history_has_best(history):
                set_brute_force_threshold(original)
        return history


def history_has_best(history: LoopHistory) -> bool:
    return bool(history.best_config)
