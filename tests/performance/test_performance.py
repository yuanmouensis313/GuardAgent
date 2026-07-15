from __future__ import annotations

import gc
import statistics
import tempfile
import time
import tracemalloc
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from guardd.config import Settings
from guardd.models.events import GuardEvent, ToolDescriptor
from guardd.policy import PolicyEngine, PolicyLoader
from guardd.service import GuardService


ROOT = Path(__file__).parents[2]


def health_event(session: str) -> GuardEvent:
    return GuardEvent(event_type="tool.before", source="test", agent_id="main", session_key=session, tool=ToolDescriptor(name="health", kind="metadata"))


class PerformanceTests(unittest.TestCase):
    def test_deterministic_decision_latency_and_100_concurrent_requests(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            engine = PolicyEngine(PolicyLoader().load(ROOT / "policies/default.yaml"), Path(temp))
            latencies = []
            for index in range(1_000):
                started = time.perf_counter_ns()
                engine.decide(health_event(f"warm-{index}"))
                latencies.append((time.perf_counter_ns() - started) / 1_000_000)
            ordered = sorted(latencies)
            p50 = statistics.median(ordered)
            p95 = ordered[int(len(ordered) * 0.95) - 1]
            self.assertLess(p50, 20, f"P50={p50:.2f}ms")
            self.assertLess(p95, 100, f"P95={p95:.2f}ms")

            def one(index: int) -> float:
                started = time.perf_counter_ns()
                engine.decide(health_event(f"concurrent-{index}"))
                return (time.perf_counter_ns() - started) / 1_000_000

            with ThreadPoolExecutor(max_workers=100) as pool:
                concurrent = list(pool.map(one, range(100)))
            concurrent_p95 = sorted(concurrent)[94]
            self.assertLess(concurrent_p95, 100, f"concurrent P95={concurrent_p95:.2f}ms")

    def test_10000_low_risk_events_have_bounded_process_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            service = GuardService(Settings(state_dir=root / "state", policy_path=ROOT / "policies/default.yaml", workspace=workspace))
            tracemalloc.start()
            try:
                for index in range(5_000):
                    service.decide(health_event(f"session-{index % 2_000}"))
                gc.collect()
                first = tracemalloc.get_traced_memory()[0]
                for index in range(5_000, 10_000):
                    service.decide(health_event(f"session-{index % 2_000}"))
                gc.collect()
                second = tracemalloc.get_traced_memory()[0]
                self.assertLessEqual(len(service._events), 5_000)
                self.assertLessEqual(len(service.correlation.states), 1_000)
                self.assertLess(second - first, 15 * 1024 * 1024, f"sustained memory grew by {(second-first)/1024/1024:.1f} MiB")
            finally:
                tracemalloc.stop()
                service.close()


if __name__ == "__main__":
    unittest.main()
