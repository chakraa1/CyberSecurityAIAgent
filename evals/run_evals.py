"""CLI entry point for the eval harness and the improvement loop.

Usage:
    python -m evals.run_evals            # run the eval suite
    python -m evals.run_evals --loop     # also run the loop-engineering demo
"""

from __future__ import annotations

import argparse
import json

from config import configure_logging, get_logger
from evals.evaluator import Evaluator
from evals.loop import ImprovementLoop

logger = get_logger(__name__)


def main() -> int:
    parser = argparse.ArgumentParser(description="CyberSecurityAIAgent evals")
    parser.add_argument("--loop", action="store_true", help="Run loop-engineering demo")
    parser.add_argument("--json", action="store_true", help="Print full JSON report")
    args = parser.parse_args()

    configure_logging()

    report = Evaluator().run_and_save()
    print("\n=== Eval Report ===")
    print(f"Passed {report.passed}/{report.total}  (pass rate: {report.pass_rate}%)")
    for c in report.cases:
        status = "PASS" if c.passed else "FAIL"
        print(f"  [{status}] {c.case_id:<22} agent={c.agent:<26} "
              f"findings={c.finding_count} severity={c.severity}")
        if not c.passed:
            for chk in c.checks:
                if not chk["passed"]:
                    print(f"        x {chk['name']}: {chk['detail']}")

    if args.json:
        print("\n" + json.dumps(report.to_dict(), indent=2))

    if args.loop:
        print("\n=== Loop Engineering: brute-force threshold sweep ===")
        history = ImprovementLoop().demo_threshold_sweep()
        for step in history.steps:
            print(f"  iter={step.iteration} "
                  f"threshold={step.config.get('brute_force_threshold')} "
                  f"pass_rate={step.pass_rate}% "
                  f"{'(accepted)' if step.accepted else ''}")
        h = history.to_dict()
        print(f"  best_config={h['best_config']} best_pass_rate={h['best_pass_rate']}% "
              f"improvement=+{h['improvement']}pp")

    return 0 if report.passed == report.total else 1


if __name__ == "__main__":
    raise SystemExit(main())
