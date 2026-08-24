"""Job/run history for the local web UI (docs/BLUEPRINT.md 8.5).

One SQLite file holds both the taxonomy and the run history, so a backup is a
file copy. A finished run's full result is written to `data/jobs/<id>.json` and
the row points at it; the database stays small and a restart does not lose what
was already computed.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from engine.storage.db import transaction


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class ResultType(str, Enum):
    RUNBOOK = "runbook"
    REJECTION_REPORT = "rejection_report"


class JobRecord(BaseModel):
    job_id: str
    filename: str
    status: JobStatus
    created_at: str
    finished_at: str | None = None
    result_type: str | None = None
    result_path: str | None = None
    error: str | None = None
    # What the run is doing right now, for the UI to show while it waits.
    stage: str | None = None

    @property
    def finished(self) -> bool:
        return self.status in {JobStatus.DONE, JobStatus.FAILED}


_COLUMNS = (
    "job_id, filename, status, created_at, finished_at, result_type, result_path, error, stage"
)


def new_job_id() -> str:
    return uuid.uuid4().hex[:12]


def create(conn: sqlite3.Connection, filename: str, *, job_id: str | None = None) -> JobRecord:
    """Record a queued job and return it."""
    record = JobRecord(
        job_id=job_id or new_job_id(),
        filename=filename,
        status=JobStatus.QUEUED,
        created_at=_utcnow(),
    )
    with transaction(conn):
        conn.execute(
            "INSERT INTO job_runs (job_id, filename, status, created_at) VALUES (?, ?, ?, ?)",
            (record.job_id, record.filename, record.status.value, record.created_at),
        )
    return record


def mark_running(conn: sqlite3.Connection, job_id: str) -> None:
    with transaction(conn):
        conn.execute(
            "UPDATE job_runs SET status = ? WHERE job_id = ?", (JobStatus.RUNNING.value, job_id)
        )


def set_stage(conn: sqlite3.Connection, job_id: str, stage: str) -> None:
    """Record what the run is doing, so a wait is legible rather than blank."""
    with transaction(conn):
        conn.execute("UPDATE job_runs SET stage = ? WHERE job_id = ?", (stage, job_id))


def mark_done(
    conn: sqlite3.Connection,
    job_id: str,
    *,
    result_type: ResultType,
    result_path: str,
) -> None:
    with transaction(conn):
        conn.execute(
            "UPDATE job_runs SET status = ?, finished_at = ?, result_type = ?, result_path = ? "
            "WHERE job_id = ?",
            (JobStatus.DONE.value, _utcnow(), result_type.value, result_path, job_id),
        )


def mark_failed(conn: sqlite3.Connection, job_id: str, error: str) -> None:
    with transaction(conn):
        conn.execute(
            "UPDATE job_runs SET status = ?, finished_at = ?, error = ? WHERE job_id = ?",
            (JobStatus.FAILED.value, _utcnow(), error[:2000], job_id),
        )


ORPHAN_REASON = (
    "The server stopped while this run was in progress. Upload the sample again to re-run it."
)


def fail_orphaned(conn: sqlite3.Connection, reason: str = ORPHAN_REASON) -> list[str]:
    """Fail runs left mid-flight by a server that is no longer here.

    A process that dies between ``mark_running`` and ``mark_done`` leaves its row
    at ``running`` permanently, and the status page polls it forever, because the
    only thing that could ever have moved it was the process that died.

    Assumes one server at a time, which the port check in ``serve.main`` enforces
    for the default port. A second instance deliberately started on another port
    would fail the first one's in-flight runs.
    """
    unfinished = (JobStatus.QUEUED.value, JobStatus.RUNNING.value)
    rows = conn.execute(
        "SELECT job_id FROM job_runs WHERE status IN (?, ?)", unfinished
    ).fetchall()
    if not rows:
        return []

    with transaction(conn):
        conn.execute(
            "UPDATE job_runs SET status = ?, finished_at = ?, error = ? WHERE status IN (?, ?)",
            (JobStatus.FAILED.value, _utcnow(), reason, *unfinished),
        )
    return [row["job_id"] for row in rows]


def get(conn: sqlite3.Connection, job_id: str) -> JobRecord | None:
    row = conn.execute(f"SELECT {_COLUMNS} FROM job_runs WHERE job_id = ?", (job_id,)).fetchone()
    return JobRecord(**dict(row)) if row else None


def list_recent(conn: sqlite3.Connection, limit: int = 50) -> list[JobRecord]:
    rows = conn.execute(
        f"SELECT {_COLUMNS} FROM job_runs ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)
    ).fetchall()
    return [JobRecord(**dict(row)) for row in rows]


def delete(conn: sqlite3.Connection, job_id: str) -> bool:
    with transaction(conn):
        cursor = conn.execute("DELETE FROM job_runs WHERE job_id = ?", (job_id,))
    return cursor.rowcount > 0


def count(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT count(*) FROM job_runs").fetchone()[0])


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
