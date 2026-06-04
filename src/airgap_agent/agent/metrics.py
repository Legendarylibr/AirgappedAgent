from __future__ import annotations

from dataclasses import dataclass
from threading import Lock


@dataclass
class MetricsSnapshot:
    runs_total: int = 0
    runs_failed: int = 0
    tool_calls_total: int = 0
    tool_denials_total: int = 0
    api_requests_total: int = 0
    sessions_active: int = 0

    def to_prometheus(self) -> str:
        lines = [
            "# HELP airgap_runs_total Agent runs started",
            "# TYPE airgap_runs_total counter",
            f"airgap_runs_total {self.runs_total}",
            "# HELP airgap_runs_failed_total Agent runs that failed validation",
            "# TYPE airgap_runs_failed_total counter",
            f"airgap_runs_failed_total {self.runs_failed}",
            "# HELP airgap_tool_calls_total Tool invocations",
            "# TYPE airgap_tool_calls_total counter",
            f"airgap_tool_calls_total {self.tool_calls_total}",
            "# HELP airgap_tool_denials_total Tool denials (policy/budget)",
            "# TYPE airgap_tool_denials_total counter",
            f"airgap_tool_denials_total {self.tool_denials_total}",
            "# HELP airgap_api_requests_total HTTP API requests",
            "# TYPE airgap_api_requests_total counter",
            f"airgap_api_requests_total {self.api_requests_total}",
            "# HELP airgap_sessions_active Active conversation sessions",
            "# TYPE airgap_sessions_active gauge",
            f"airgap_sessions_active {self.sessions_active}",
        ]
        return "\n".join(lines) + "\n"


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = Lock()
        self._runs_total = 0
        self._runs_failed = 0
        self._tool_calls_total = 0
        self._tool_denials_total = 0
        self._api_requests_total = 0
        self._sessions_active = 0

    def inc_run(self) -> None:
        with self._lock:
            self._runs_total += 1

    def inc_run_failed(self) -> None:
        with self._lock:
            self._runs_failed += 1

    def inc_tool_calls(self, count: int = 1) -> None:
        with self._lock:
            self._tool_calls_total += count

    def inc_tool_denials(self, count: int = 1) -> None:
        with self._lock:
            self._tool_denials_total += count

    def inc_api_request(self) -> None:
        with self._lock:
            self._api_requests_total += 1

    def set_sessions_active(self, count: int) -> None:
        with self._lock:
            self._sessions_active = count

    def snapshot(self) -> MetricsSnapshot:
        with self._lock:
            return MetricsSnapshot(
                runs_total=self._runs_total,
                runs_failed=self._runs_failed,
                tool_calls_total=self._tool_calls_total,
                tool_denials_total=self._tool_denials_total,
                api_requests_total=self._api_requests_total,
                sessions_active=self._sessions_active,
            )
