from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from guardd.audit import AuditStore
from guardd.config import Settings
from guardd.doctor import run_doctor
from guardd.security import sanitize


class DiagnosticJobError(ValueError):
    pass


class DiagnosticJobManager:
    def __init__(
        self,
        settings: Settings,
        store: AuditStore,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
        max_history: int = 20,
    ):
        self.settings = settings
        self.store = store
        self.on_event = on_event
        self.max_history = max_history
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="guard-doctor")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def start(self, operator: str) -> dict[str, Any]:
        with self._lock:
            if any(job["status"] in {"queued", "running"} for job in self._jobs.values()):
                raise DiagnosticJobError("a diagnostic job is already running")
            job_id = str(uuid4())
            job = {"job_id": job_id, "operator": operator, "status": "queued", "started_at": self._now(), "completed_at": None, "result": None}
            self._jobs[job_id] = job
            self.store.record_diagnostic_job(job_id, operator, "queued", started_at=job["started_at"])
            self._executor.submit(self._run, job_id)
            return dict(job)

    def _run(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job["status"] = "running"
            self.store.record_diagnostic_job(job_id, job["operator"], "running", started_at=job["started_at"])
        try:
            report = run_doctor(self.settings)
            clean, _ = sanitize(report, extra_patterns=self.store.secret_patterns)
            status = "completed"
        except Exception as exc:  # diagnostics must not terminate guardd
            clean = {"overall": "fail", "error": str(exc)[:1000], "checks": []}
            status = "failed"
        completed = self._now()
        with self._lock:
            job.update({"status": status, "completed_at": completed, "result": clean})
            self.store.record_diagnostic_job(job_id, job["operator"], status, clean, job["started_at"], completed)
            if len(self._jobs) > self.max_history:
                oldest = sorted(self._jobs.values(), key=lambda item: item["started_at"])[0]
                self._jobs.pop(oldest["job_id"], None)
        if self.on_event:
            self.on_event("diagnostic.completed", {"job_id": job_id, "status": status})

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
