from __future__ import annotations

import json
import statistics
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardd.models.events import GuardEvent, ToolDescriptor
from guardd.policy import PolicyEngine, PolicyLoader


def event(index: int) -> GuardEvent:
    return GuardEvent(event_type="tool.before", source="test", agent_id="benchmark", session_key=f"bench-{index}", tool=ToolDescriptor(name="health", kind="metadata"))


def main() -> None:
    with tempfile.TemporaryDirectory() as temp:
        engine = PolicyEngine(PolicyLoader().load(Path("policies/default.yaml")), Path(temp))

        def timed(index: int) -> float:
            started = time.perf_counter_ns()
            engine.decide(event(index))
            return (time.perf_counter_ns() - started) / 1_000_000

        sequential = [timed(index) for index in range(10_000)]
        with ThreadPoolExecutor(max_workers=100) as pool:
            concurrent = list(pool.map(timed, range(10_000, 10_100)))
    report = {
        "events": 10_000,
        "p50_ms": statistics.median(sequential),
        "p95_ms": sorted(sequential)[9_499],
        "concurrent_requests": 100,
        "concurrent_p95_ms": sorted(concurrent)[94],
    }
    print(json.dumps(report, indent=2))
    if report["p50_ms"] >= 20 or report["p95_ms"] >= 100 or report["concurrent_p95_ms"] >= 100:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
