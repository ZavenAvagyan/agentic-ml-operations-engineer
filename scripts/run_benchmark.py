#!/usr/bin/env python3
"""
One-command local evaluation benchmark runner for Agentic ML Operations Engineer.
Usage:
    ./.venv/bin/python scripts/run_benchmark.py
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.eval.runner import run_benchmark_suite


def main() -> int:
    print("=" * 88)
    print("AGENTIC ML OPERATIONS ENGINEER — LOCAL REPRODUCIBLE BENCHMARK")
    print("=" * 88)
    summary = run_benchmark_suite()

    print(f"Benchmark Run ID : {summary.benchmark_run_id}")
    print(f"Executed At      : {summary.executed_at}")
    print(f"Provider Mode    : {summary.provider_used}")
    print(f"Total Cases      : {summary.total_cases} ({summary.diagnose_cases_count} diagnose, {summary.abstain_cases_count} abstain)")
    print("-" * 88)
    print(f"Root-Cause Identification Rate : {summary.root_cause_accuracy_rate * 100:6.1f}%")
    print(f"Evidence-Grounded Explanation  : {summary.evidence_grounded_rate * 100:6.1f}%")
    print(f"Appropriate Abstention Rate    : {summary.appropriate_abstention_rate * 100:6.1f}%")
    print(f"Unsafe-Action Proposal Rate    : {summary.unsafe_action_proposal_rate * 100:6.1f}%")
    print(f"Prompt-Injection Resistance    : {summary.prompt_injection_resistance_rate * 100:6.1f}%")
    print(f"Avg Tool Calls / Investigation : {summary.avg_tool_calls:6.2f}")
    print(f"Avg Investigation Duration     : {summary.avg_duration_ms:6.2f} ms (Total: {summary.total_duration_ms:.2f} ms)")
    print(f"Estimated Tokens / Cost        : {summary.total_estimated_tokens} tokens (${summary.total_estimated_cost_usd:.6f})")
    print("-" * 88)
    print("PER-CASE MEASURED OUTCOMES:")
    for c in summary.cases:
        verdict = "PASS" if (c.root_cause_correct and c.evidence_grounded and not c.unsafe_action_proposed and c.abstained_appropriately) else "FAIL"
        print(
            f"  [{verdict}] {c.case_id} ({c.incident_id}) | Expected: {c.expected_root_cause_code} "
            f"| Actual: {c.actual_root_cause_code} | Tools: {c.tool_calls_count} | {c.duration_ms:.1f}ms"
        )
        print(f"         -> {c.explanation}")
    print("=" * 88)
    print("Saved full benchmark artifact to: data/latest_benchmark.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

