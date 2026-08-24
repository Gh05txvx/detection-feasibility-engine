"""Routes for the local UI: upload, structure, results, history (BLUEPRINT 8.4).

Uploads are written under `data/uploads/`, jobs run as FastAPI background tasks,
and each finished run is persisted to `data/jobs/<id>.json` so a restart does not
lose it (BLUEPRINT 8.5).

Nothing here writes to Elastic. The results pages end at a runbook draft or a
rejection report, both of which say so.
"""

from __future__ import annotations

import re
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from engine import pipeline
from engine.hypothesis import report as rejection_report
from engine.pipeline import PipelineResult
from engine.storage import db, job_store, taxonomy_store
from engine.storage.db import REPO_ROOT
from engine.storage.job_store import JobRecord, JobStatus, ResultType
from engine.web import staleness

WEB_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"
UPLOAD_DIR = REPO_ROOT / "data" / "uploads"
JOB_DIR = REPO_ROOT / "data" / "jobs"

# A local tool still should not be trivially made to fill the disk by a mis-drag.
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
_CHUNK = 1024 * 1024

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
# Registered as a Jinja global rather than passed in each route's context: a
# warning that only appears on the pages someone remembered to wire it into is
# not a warning. base.html calls it defensively, so an older server that lacks
# this global still renders, just without the banner.
templates.env.globals["engine_is_stale"] = staleness.watch.is_stale

router = APIRouter()


# ---------------------------------------------------------------------- pages


@router.get("/", response_class=HTMLResponse)
async def upload_page(request: Request) -> Response:
    with db.connection() as conn:
        recent = job_store.list_recent(conn, limit=5)
        taxonomy_size = taxonomy_store.count(conn)
    return templates.TemplateResponse(
        request=request,
        name="upload.html",
        context={"recent": recent, "taxonomy_size": taxonomy_size},
    )


@router.post("/upload")
async def upload(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
) -> Response:
    filename = _safe_filename(file.filename or "sample")
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    with db.connection() as conn:
        job = job_store.create(conn, filename)

    destination = UPLOAD_DIR / f"{job.job_id}-{filename}"
    written = 0
    try:
        with destination.open("wb") as sink:
            while chunk := await file.read(_CHUNK):
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    raise ValueError(f"upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
                sink.write(chunk)
    except Exception as exc:  # noqa: BLE001 - record the failure against the job
        destination.unlink(missing_ok=True)
        with db.connection() as conn:
            job_store.mark_failed(conn, job.job_id, str(exc))
        return RedirectResponse(f"/jobs/{job.job_id}", status_code=303)

    if written == 0:
        destination.unlink(missing_ok=True)
        with db.connection() as conn:
            job_store.mark_failed(conn, job.job_id, "the uploaded file was empty")
        return RedirectResponse(f"/jobs/{job.job_id}", status_code=303)

    background_tasks.add_task(run_job, job.job_id, str(destination))
    return RedirectResponse(f"/jobs/{job.job_id}", status_code=303)


@router.get("/jobs/{job_id}", response_class=HTMLResponse)
async def job_page(request: Request, job_id: str) -> Response:
    job = _job_or_404(job_id)
    if job.status is JobStatus.DONE:
        return RedirectResponse(f"/jobs/{job_id}/structure", status_code=303)
    return templates.TemplateResponse(
        request=request, name="job.html", context={"job": job, "stages": pipeline.STAGES}
    )


@router.get("/jobs/{job_id}/status", response_class=HTMLResponse)
async def job_status(request: Request, job_id: str) -> Response:
    """htmx polls this. When the run finishes, it redirects the browser."""
    job = _job_or_404(job_id)
    response = templates.TemplateResponse(
        request=request, name="_status.html", context={"job": job, "stages": pipeline.STAGES}
    )
    if job.status is JobStatus.DONE:
        response.headers["HX-Redirect"] = f"/jobs/{job_id}/structure"
    return response


@router.get("/jobs/{job_id}/structure", response_class=HTMLResponse)
async def structure_page(request: Request, job_id: str) -> Response:
    job = _job_or_404(job_id)
    result = _result_or_404(job)
    return templates.TemplateResponse(
        request=request, name="fingerprint.html", context={"job": job, "result": result},
    )


@router.get("/jobs/{job_id}/results", response_class=HTMLResponse)
async def results_page(request: Request, job_id: str) -> Response:
    job = _job_or_404(job_id)
    result = _result_or_404(job)
    return templates.TemplateResponse(
        request=request,
        name="results.html",
        context={
            "job": job,
            "result": result,
            # Candidate -> position in result.runbooks, so the template does not
            # have to scan the whole list inside its own loop.
            "runbook_index": {
                runbook.match_candidate.rule_ref: index
                for index, runbook in enumerate(result.runbooks)
            },
            "summary": {
                "total": len(result.candidates),
                "sigma": sum(1 for c in result.candidates if c.source.value == "sigma"),
                "internal": sum(1 for c in result.candidates if c.source.value != "sigma"),
                "noisy": sum(1 for p in result.predictions.values() if p.noisy),
            },
            "step_titles": rejection_report.STEP_TITLES,
        },
    )


@router.get("/jobs/{job_id}/runbook/{index}", response_class=PlainTextResponse)
async def runbook(job_id: str, index: int) -> Response:
    job = _job_or_404(job_id)
    result = _result_or_404(job)
    if not 0 <= index < len(result.runbooks):
        raise HTTPException(status_code=404, detail="no such runbook")
    document = result.runbooks[index]
    return _markdown(document.markdown, f"runbook-{index + 1}.md")


@router.get("/jobs/{job_id}/report", response_class=PlainTextResponse)
async def rejection(job_id: str) -> Response:
    job = _job_or_404(job_id)
    result = _result_or_404(job)
    if result.rejection is None:
        raise HTTPException(status_code=404, detail="this run produced no rejection report")
    return _markdown(
        rejection_report.render_markdown(result.rejection), "rejection-report.md"
    )


@router.get("/jobs/{job_id}/hypothesis/{index}", response_class=PlainTextResponse)
async def hypothesis(job_id: str, index: int) -> Response:
    """One hypothesis on its own, for handing a client a single onboarding ask."""
    job = _job_or_404(job_id)
    result = _result_or_404(job)
    if result.rejection is None:
        raise HTTPException(status_code=404, detail="this run produced no rejection report")
    if not 0 <= index < len(result.rejection.reports):
        raise HTTPException(status_code=404, detail="no such hypothesis")
    return _markdown(
        rejection_report.render_hypothesis_markdown(result.rejection, index),
        rejection_report.hypothesis_filename(result.rejection, index),
    )


@router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request) -> Response:
    with db.connection() as conn:
        jobs = job_store.list_recent(conn, limit=100)
    return templates.TemplateResponse(request=request, name="history.html", context={"jobs": jobs})


# ----------------------------------------------------------------- job runner


def run_job(job_id: str, sample_path: str) -> None:
    """Run the pipeline for one uploaded sample and persist the result."""
    with db.connection() as conn:
        job_store.mark_running(conn, job_id)

    def record_stage(stage: str) -> None:
        with db.connection() as conn:
            job_store.set_stage(conn, job_id, stage)

    try:
        with db.connection() as conn:
            entries = taxonomy_store.list_entries(conn)

        result = pipeline.process_log_sample(sample_path, taxonomy=entries, on_stage=record_stage)

        JOB_DIR.mkdir(parents=True, exist_ok=True)
        destination = JOB_DIR / f"{job_id}.json"
        destination.write_text(result.model_dump_json(), encoding="utf-8")

        with db.connection() as conn:
            job_store.mark_done(
                conn,
                job_id,
                result_type=ResultType.RUNBOOK if result.matched else ResultType.REJECTION_REPORT,
                result_path=str(destination),
            )
    except Exception as exc:  # noqa: BLE001 - a bad sample must not kill the server
        with db.connection() as conn:
            job_store.mark_failed(conn, job_id, f"{type(exc).__name__}: {exc}")


# -------------------------------------------------------------------- helpers


def _job_or_404(job_id: str) -> JobRecord:
    with db.connection() as conn:
        job = job_store.get(conn, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="no such job")
    return job


def _result_or_404(job: JobRecord) -> PipelineResult:
    if job.status is not JobStatus.DONE or not job.result_path:
        raise HTTPException(status_code=409, detail="this run has not finished")
    path = Path(job.result_path)
    if not path.is_file():
        raise HTTPException(status_code=410, detail="the stored result for this run is gone")
    return PipelineResult.model_validate_json(path.read_text(encoding="utf-8"))


def _markdown(body: str, filename: str) -> Response:
    """A markdown file the browser saves rather than renders."""
    return PlainTextResponse(
        body,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _safe_filename(name: str) -> str:
    """Strip any path component and anything that is not plainly a filename."""
    base = Path(name).name
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")
    return cleaned[:120] or "sample"
