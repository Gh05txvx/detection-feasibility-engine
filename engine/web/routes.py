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
from engine.profiling import ecs_export
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

RECENT_LIMIT = 5
HISTORY_LIMIT = 100

# Job ids are `uuid4().hex[:12]`. Checked again before any path is built from one,
# because a delete that takes an id from the URL and hands it to a glob is exactly
# where a traversal would pay off.
_JOB_ID_RE = re.compile(r"^[0-9a-f]{6,32}$")

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
# Registered as a Jinja global rather than passed in each route's context: a
# warning that only appears on the pages someone remembered to wire it into is
# not a warning. base.html calls it defensively, so an older server that lacks
# this global still renders, just without the banner.
templates.env.globals["engine_is_stale"] = staleness.watch.is_stale
# One spelling of an elapsed time across the pages and the downloaded markdown.
templates.env.globals["span"] = rejection_report.humanise_span

router = APIRouter()


# ---------------------------------------------------------------------- pages


@router.get("/", response_class=HTMLResponse)
async def upload_page(request: Request) -> Response:
    with db.connection() as conn:
        recent = job_store.list_recent(conn, limit=RECENT_LIMIT)
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
        request=request,
        name="fingerprint.html",
        context={"job": job, "result": result, "export": _ecs_export(job, result)},
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


@router.get("/jobs/{job_id}/ecs-pipeline", response_class=PlainTextResponse)
async def ecs_pipeline(job_id: str) -> Response:
    """The sample's fields, normalized to ECS, as an ingest pipeline body.

    Downloaded, reviewed, and applied by a person - `PUT _ingest/pipeline/<id>`
    is theirs to run. BLUEPRINT 5.8 is why nothing here talks to a cluster.
    """
    job = _job_or_404(job_id)
    export = _ecs_export(job, _result_or_404(job))
    return _json(export.pipeline_json, export.pipeline_filename)


@router.get("/jobs/{job_id}/ecs-template", response_class=PlainTextResponse)
async def ecs_template(job_id: str) -> Response:
    """The index template that types what the pipeline produces."""
    job = _job_or_404(job_id)
    export = _ecs_export(job, _result_or_404(job))
    return _json(export.template_json, export.template_filename)


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
        jobs = job_store.list_recent(conn, limit=HISTORY_LIMIT)
    return templates.TemplateResponse(request=request, name="history.html", context={"jobs": jobs})


@router.delete("/jobs/{job_id}", response_class=HTMLResponse)
async def delete_job(request: Request, job_id: str, view: str = "history") -> Response:
    """Delete one run: its row, its stored result, and the sample uploaded for it.

    The uploaded sample is the point. It is the one artefact here that holds real
    client log data, and until now nothing removed it - a run could be forgotten
    from the UI while its sample sat on disk indefinitely.

    Returns the whole re-rendered panel rather than an empty row, so the heading
    count, the empty state and the rows cannot end up disagreeing.
    """
    job = _job_or_404(job_id)
    if not job.finished:
        raise HTTPException(
            status_code=409,
            detail="this run is still going; it would write its result after the delete",
        )

    _remove_job_files(job)
    limit = RECENT_LIMIT if view == "recent" else HISTORY_LIMIT
    with db.connection() as conn:
        job_store.delete(conn, job.job_id)
        jobs = job_store.list_recent(conn, limit=limit)

    return templates.TemplateResponse(
        request=request, name="_runs.html", context={"jobs": jobs, "view": view}
    )


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


def _remove_job_files(job: JobRecord) -> None:
    """Delete what one run left on disk: its uploaded sample and its result.

    Both paths are checked against the directory they are supposed to be under
    before anything is unlinked. `result_path` comes out of the database and the
    id comes off the URL; neither is trusted to be inside its directory just
    because it normally is.

    A file already gone is not an error - the row is what the user asked to be
    rid of, and refusing to finish because a file was cleaned up by hand would
    leave them stuck.
    """
    if not _JOB_ID_RE.match(job.job_id):
        return

    for path in UPLOAD_DIR.glob(f"{job.job_id}-*"):
        _unlink_within(path, UPLOAD_DIR)

    if job.result_path:
        _unlink_within(Path(job.result_path), JOB_DIR)


def _unlink_within(path: Path, directory: Path) -> None:
    """Unlink `path` only if it really resolves to a file inside `directory`."""
    try:
        resolved = path.resolve()
        if not resolved.is_relative_to(directory.resolve()):
            return
        if resolved.is_file():
            resolved.unlink()
    except OSError:
        # Locked by a virus scanner, or on a volume that vanished. The row still
        # goes; a file that could not be removed is not a reason to keep it.
        pass


def _ecs_export(job: JobRecord, result: PipelineResult) -> ecs_export.EcsExport:
    """Derived on each request rather than stored: it is a pure function of the
    result, and a run persisted before this existed would otherwise have none."""
    return ecs_export.build(result.fingerprint, result.ecs_gap, sample_name=job.filename)


def _markdown(body: str, filename: str) -> Response:
    """A markdown file the browser saves rather than renders."""
    return PlainTextResponse(
        body,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _json(body: str, filename: str) -> Response:
    """A JSON file the browser saves rather than renders."""
    return PlainTextResponse(
        body,
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _safe_filename(name: str) -> str:
    """Strip any path component and anything that is not plainly a filename."""
    base = Path(name).name
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")
    return cleaned[:120] or "sample"
