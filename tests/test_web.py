"""Web layer tests: the loopback guarantee, the four pages, and the job lifecycle."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from engine.storage import db, job_store, taxonomy_store
from engine.storage.job_store import JobStatus
from engine.storage.taxonomy_store import TaxonomyEntry
from engine.web import routes, serve, staleness

FIXTURES = Path(__file__).parent / "fixtures"
CLOUDFLARE = FIXTURES / "cloudflare_waf_firewall_events.csv"
APPLIANCE = FIXTURES / "minimal_appliance_syslog.csv"
NO_CORPUS = Path("does-not-exist")


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    """A throwaway database, upload dir, and job dir, with the corpora switched off."""
    database = tmp_path / "engine.db"
    db.init_db(database)
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", database)
    monkeypatch.setattr(routes, "UPLOAD_DIR", tmp_path / "uploads")
    monkeypatch.setattr(routes, "JOB_DIR", tmp_path / "jobs")

    original = routes.pipeline.process_log_sample

    def offline(path, **kwargs):
        # Keep tests independent of the multi-hundred-megabyte clones.
        kwargs.setdefault("sigma_corpus", NO_CORPUS)
        kwargs.setdefault("integrations_corpus", NO_CORPUS)
        return original(path, **kwargs)

    monkeypatch.setattr(routes.pipeline, "process_log_sample", offline)
    return tmp_path


@pytest.fixture()
def client(workspace):
    return TestClient(serve.create_app())


def _seed_taxonomy() -> None:
    entry = TaxonomyEntry(
        slug="cloudflare-waf-sqli",
        name="Cloudflare WAF - SQL injection attempt",
        logsource_category="webserver",
        logsource_product="cloudflare",
        logsource_service="firewall_events",
        required_fields=["ClientIP", "Action"],
        detection_logic={"waf": {"Source": ["waf"]}, "condition": "waf"},
        mitre_techniques=["T1190"],
        confidence=0.8,
    )
    with db.connection() as conn:
        taxonomy_store.upsert(conn, entry)


def _upload(client: TestClient, path: Path):
    with path.open("rb") as handle:
        return client.post(
            "/upload", files={"file": (path.name, handle, "text/csv")}, follow_redirects=False
        )


# ------------------------------------------------------- the loopback promise


def test_server_binds_loopback_only():
    """BLUEPRINT 8.2: on any non-loopback address another machine could read the
    client's raw logs out of this tool."""
    import ipaddress

    assert ipaddress.ip_address(serve.HOST).is_loopback

    # The bind address must not be reachable from argv either.
    with pytest.raises(SystemExit):
        serve.main(["--host", "0.0.0.0"])

    source = Path(serve.__file__).read_text(encoding="utf-8")
    assert "host=HOST" in source, "uvicorn must be given the module constant, not a variable"


def test_port_check_detects_a_bound_port():
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as taken:
        taken.bind((serve.HOST, 0))
        taken.listen(1)
        port = taken.getsockname()[1]
        assert serve.port_is_free(port) is False

    assert serve.port_is_free(port) is True


def test_uploaded_filenames_cannot_escape_the_upload_directory():
    assert routes._safe_filename("../../etc/passwd") == "passwd"
    assert routes._safe_filename("a/b/c.csv") == "c.csv"
    assert "\\" not in routes._safe_filename(r"..\..\windows\system32\x.csv")
    assert routes._safe_filename("") == "sample"


# --------------------------------------------------------------- staleness


def _py_file(directory: Path, name: str, body: str = "x = 1\n") -> Path:
    path = directory / name
    path.write_text(body, encoding="utf-8")
    return path


def test_watch_says_nothing_before_it_has_been_marked(tmp_path):
    """An unmarked watch must not warn; that would flag every correct server."""
    watch = staleness.StalenessWatch(tmp_path, recheck_seconds=0)
    _py_file(tmp_path, "a.py")

    assert watch.is_stale() is False


def test_watch_is_quiet_while_the_code_is_unchanged(tmp_path):
    watch = staleness.StalenessWatch(tmp_path, recheck_seconds=0)
    _py_file(tmp_path, "a.py")
    watch.mark_started()

    assert watch.is_stale() is False


def test_watch_notices_an_edited_file(tmp_path):
    watch = staleness.StalenessWatch(tmp_path, recheck_seconds=0)
    edited = _py_file(tmp_path, "a.py")
    watch.mark_started()

    edited.write_text("x = 2\n", encoding="utf-8")
    import os

    os.utime(edited, (1_800_000_000, 1_800_000_000))

    assert watch.is_stale() is True


def test_watch_notices_a_new_file(tmp_path):
    watch = staleness.StalenessWatch(tmp_path, recheck_seconds=0)
    _py_file(tmp_path, "a.py")
    watch.mark_started()

    _py_file(tmp_path, "b.py")

    assert watch.is_stale() is True


def test_watch_ignores_everything_that_is_not_python(tmp_path):
    """Templates reload themselves and static files are read per request."""
    watch = staleness.StalenessWatch(tmp_path, recheck_seconds=0)
    _py_file(tmp_path, "a.py")
    watch.mark_started()

    (tmp_path / "page.html").write_text("<p>edited</p>", encoding="utf-8")

    assert watch.is_stale() is False


def test_the_banner_appears_when_the_code_has_moved_on(client, monkeypatch):
    monkeypatch.setitem(routes.templates.env.globals, "engine_is_stale", lambda: True)

    body = client.get("/").text

    assert "running older code than what is on disk" in body
    assert "run.bat" in body


def test_no_banner_on_a_current_server(client):
    assert "running older code" not in client.get("/").text


def test_pages_still_render_for_a_server_that_lacks_the_global(client, monkeypatch):
    """The banner exists for stale servers, so it must not itself break one."""
    monkeypatch.delitem(routes.templates.env.globals, "engine_is_stale")

    for page in ("/", "/history"):
        assert client.get(page).status_code == 200


# ------------------------------------------------------------------- pages


def test_upload_page_renders(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "Drop a CSV" in response.text
    assert "/static/htmx.min.js" in response.text


def test_static_assets_are_served_locally(client):
    """Nothing may be fetched from a CDN; the tool has to work air-gapped."""
    for asset in ("/static/htmx.min.js", "/static/app.css"):
        assert client.get(asset).status_code == 200

    page = client.get("/").text
    assert "http://unpkg" not in page and "https://" not in page


def test_history_page_renders_when_empty(client):
    response = client.get("/history")

    assert response.status_code == 200
    assert "Nothing assessed yet" in response.text


def test_unknown_job_is_a_404_with_something_to_click(client):
    response = client.get("/jobs/deadbeef")

    assert response.status_code == 404
    assert "Not found" in response.text
    assert "no such job" in response.text
    assert "Start a new scan" in response.text
    assert client.get("/jobs/deadbeef/structure").status_code == 404


def test_a_crash_renders_an_actionable_page_not_a_bare_500(workspace):
    """The traceback goes to a terminal nobody is watching; the browser gets this."""
    from jinja2 import UndefinedError

    from fastapi.testclient import TestClient

    quiet = TestClient(serve.create_app(), raise_server_exceptions=False)
    _seed_taxonomy()
    job_id = _upload(quiet, CLOUDFLARE).headers["location"].rsplit("/", 1)[-1]

    def boom(job):
        raise UndefinedError("'step_titles' is undefined")

    original = routes._result_or_404
    routes._result_or_404 = boom
    try:
        response = quiet.get(f"/jobs/{job_id}/results")
    finally:
        routes._result_or_404 = original

    assert response.status_code == 500
    assert "Something went wrong" in response.text
    assert "UndefinedError" in response.text
    # The specific hint for the failure mode of editing code while it runs.
    assert "start run.bat again" in response.text


# ------------------------------------------------------------ job lifecycle


def test_upload_runs_the_pipeline_and_records_the_job(client):
    _seed_taxonomy()

    response = _upload(client, CLOUDFLARE)

    assert response.status_code == 303
    job_id = response.headers["location"].rsplit("/", 1)[-1]

    with db.connection() as conn:
        job = job_store.get(conn, job_id)
    assert job is not None
    assert job.status is JobStatus.DONE
    assert job.result_type == "runbook"
    assert Path(job.result_path).is_file()


def test_finished_job_redirects_to_the_structure_page(client):
    _seed_taxonomy()
    job_id = _upload(client, CLOUDFLARE).headers["location"].rsplit("/", 1)[-1]

    response = client.get(f"/jobs/{job_id}", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"].endswith("/structure")


def test_structure_page_shows_the_fingerprint_and_fields(client):
    _seed_taxonomy()
    job_id = _upload(client, CLOUDFLARE).headers["location"].rsplit("/", 1)[-1]

    response = client.get(f"/jobs/{job_id}/structure")

    assert response.status_code == 200
    assert "cloudflare" in response.text
    assert "ClientRequestQuery" in response.text
    # The record and field counts are stat tiles.
    assert '<span class="value">37</span>' in response.text
    assert '<span class="value">19</span>' in response.text
    assert "records" in response.text


def test_results_page_shows_candidates_with_type_and_backtest(client):
    _seed_taxonomy()
    job_id = _upload(client, CLOUDFLARE).headers["location"].rsplit("/", 1)[-1]

    response = client.get(f"/jobs/{job_id}/results")

    assert response.status_code == 200
    assert "internal:cloudflare-waf-sqli" in response.text
    assert "custom_query" in response.text
    assert "sample events match" in response.text
    assert "Download draft runbook" in response.text


def test_a_candidate_card_shows_the_events_it_fired_on(client):
    """A match rate is a number; the events are what a reviewer can check."""
    _seed_taxonomy()
    job_id = _upload(client, CLOUDFLARE).headers["location"].rsplit("/", 1)[-1]

    response = client.get(f"/jobs/{job_id}/results")

    assert "this fired on" in response.text
    assert "Event time" in response.text
    assert "Datetime" in response.text
    # A value out of the sample itself, not just a count of them.
    assert "shop.example.co.id" in response.text


def test_a_rejected_card_names_the_field_that_is_missing(client):
    """'Rejected' is a verdict; the missing field is the reason to act on."""
    job_id = _upload(client, APPLIANCE).headers["location"].rsplit("/", 1)[-1]

    response = client.get(f"/jobs/{job_id}/results")

    assert "The sample carries no field for" in response.text
    assert "Evidence needed" in response.text
    assert "user identity" in response.text
    # And the sample's own events, so the gap is read against the data.
    assert "What the log actually looks like" in response.text
    assert "vpn-gw-01" in response.text


def test_runbook_downloads_as_markdown(client):
    _seed_taxonomy()
    job_id = _upload(client, CLOUDFLARE).headers["location"].rsplit("/", 1)[-1]

    response = client.get(f"/jobs/{job_id}/runbook/0")

    assert response.status_code == 200
    assert "# Runbook (draft)" in response.text
    assert "attachment" in response.headers["content-disposition"]
    assert client.get(f"/jobs/{job_id}/runbook/99").status_code == 404


def test_no_match_sample_shows_the_rejection_report(client):
    job_id = _upload(client, APPLIANCE).headers["location"].rsplit("/", 1)[-1]

    response = client.get(f"/jobs/{job_id}/results")

    assert response.status_code == 200
    assert "No match" in response.text
    assert "not the same as" in response.text
    assert "Onboarding requirements" in response.text
    assert "Download this hypothesis" in response.text

    download = client.get(f"/jobs/{job_id}/report")
    assert download.status_code == 200
    assert "# Detection feasibility: rejection report" in download.text


# ----------------------------------------------------------- deleting a run


def test_deleting_a_run_removes_its_uploaded_sample_and_result(client, workspace):
    """The sample is the point: it is the one artefact holding real client logs."""
    _seed_taxonomy()
    job_id = _upload(client, CLOUDFLARE).headers["location"].rsplit("/", 1)[-1]

    uploads = list((workspace / "uploads").glob(f"{job_id}-*"))
    result_file = workspace / "jobs" / f"{job_id}.json"
    assert uploads and result_file.is_file()

    response = client.delete(f"/jobs/{job_id}?view=history")

    assert response.status_code == 200
    assert not list((workspace / "uploads").glob(f"{job_id}-*"))
    assert not result_file.exists()
    with db.connection() as conn:
        assert job_store.get(conn, job_id) is None
    # The panel comes back re-rendered, so the count cannot drift from the rows.
    assert 'id="runs-panel"' in response.text
    assert job_id not in response.text
    assert "Nothing assessed yet" in response.text


def test_the_panel_that_comes_back_matches_the_page_it_was_deleted_from(client):
    _seed_taxonomy()
    keep = _upload(client, APPLIANCE).headers["location"].rsplit("/", 1)[-1]
    drop = _upload(client, CLOUDFLARE).headers["location"].rsplit("/", 1)[-1]

    recent = client.delete(f"/jobs/{drop}?view=recent")

    assert "Recent runs" in recent.text
    assert "All runs" in recent.text
    assert keep in recent.text
    # The upload page's compact table has no Finished column and no filter.
    assert "Finished" not in recent.text
    assert "Filter runs" not in recent.text


def test_a_run_still_going_cannot_be_deleted(client, workspace):
    """It would write its result file after the delete, orphaning it."""
    with db.connection() as conn:
        job = job_store.create(conn, "in-flight.csv")
        job_store.mark_running(conn, job.job_id)

    response = client.delete(f"/jobs/{job.job_id}")

    assert response.status_code == 409
    with db.connection() as conn:
        assert job_store.get(conn, job.job_id) is not None


def test_delete_will_not_follow_a_result_path_out_of_its_directory(client, workspace):
    """The path comes out of the database; it is not trusted for being usual."""
    outsider = workspace / "not-a-job-result.json"
    outsider.write_text("{}", encoding="utf-8")

    with db.connection() as conn:
        job = job_store.create(conn, "tampered.csv")
        job_store.mark_done(
            conn, job.job_id,
            result_type=job_store.ResultType.RUNBOOK,
            result_path=str(outsider),
        )

    response = client.delete(f"/jobs/{job.job_id}")

    assert response.status_code == 200
    assert outsider.is_file(), "a file outside the job directory must survive"
    with db.connection() as conn:
        assert job_store.get(conn, job.job_id) is None


def test_deleting_an_unknown_run_is_a_404(client):
    assert client.delete("/jobs/deadbeef0000").status_code == 404


def test_a_finished_run_offers_delete_and_an_unfinished_one_does_not(client):
    with db.connection() as conn:
        running = job_store.create(conn, "still-going.csv")
        job_store.mark_running(conn, running.job_id)
        finished = job_store.create(conn, "finished.csv")
        job_store.mark_failed(conn, finished.job_id, "nope")

    page = client.get("/history").text

    assert f'hx-delete="/jobs/{finished.job_id}?view=history"' in page
    assert f"/jobs/{running.job_id}?view=" not in page
    assert "Still running. It can be deleted once it finishes." in page
    # Deleting is destructive and irreversible, so it asks first.
    assert "hx-confirm=" in page
    assert "cannot be undone" in page


def test_one_hypothesis_downloads_on_its_own(client):
    """What you hand a client is one onboarding ask, not a report to search."""
    job_id = _upload(client, APPLIANCE).headers["location"].rsplit("/", 1)[-1]

    response = client.get(f"/jobs/{job_id}/hypothesis/0")

    assert response.status_code == 200
    assert response.text.startswith("# Detection feasibility: ")
    assert "## What this needs" in response.text
    assert "text/markdown" in response.headers["content-type"]
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert "rejection-" in disposition and disposition.endswith('.md"')

    assert client.get(f"/jobs/{job_id}/hypothesis/99").status_code == 404


def test_a_matched_run_has_no_hypothesis_to_download(client):
    _seed_taxonomy()
    job_id = _upload(client, CLOUDFLARE).headers["location"].rsplit("/", 1)[-1]

    assert client.get(f"/jobs/{job_id}/hypothesis/0").status_code == 404


def test_status_fragment_redirects_once_the_run_is_done(client):
    _seed_taxonomy()
    job_id = _upload(client, CLOUDFLARE).headers["location"].rsplit("/", 1)[-1]

    response = client.get(f"/jobs/{job_id}/status")

    assert response.status_code == 200
    assert response.headers["HX-Redirect"].endswith("/structure")


def test_status_fragment_polls_while_running(client):
    with db.connection() as conn:
        job = job_store.create(conn, "pending.csv")
        job_store.mark_running(conn, job.job_id)

    response = client.get(f"/jobs/{job.job_id}/status")

    assert 'hx-trigger="every 1s"' in response.text
    assert client.get(f"/jobs/{job.job_id}/results").status_code == 409


def test_status_shows_the_stage_the_run_has_reached(client):
    """A wait long enough to matter deserves more than a spinner."""
    from engine import pipeline

    with db.connection() as conn:
        job = job_store.create(conn, "pending.csv")
        job_store.mark_running(conn, job.job_id)
        job_store.set_stage(conn, job.job_id, pipeline.STAGES[2])

    response = client.get(f"/jobs/{job.job_id}/status")

    for stage in pipeline.STAGES:
        assert stage in response.text
    # Earlier stages read as done, the recorded one as current.
    assert response.text.index('class="done"') < response.text.index('class="current"')


def test_finished_job_records_every_stage_it_passed(client):
    _seed_taxonomy()
    from engine import pipeline

    job_id = _upload(client, CLOUDFLARE).headers["location"].rsplit("/", 1)[-1]

    with db.connection() as conn:
        job = job_store.get(conn, job_id)
    assert job.stage == pipeline.STAGES[-1]


def test_a_run_orphaned_by_a_restart_is_failed_when_the_next_server_boots(workspace):
    with db.connection() as conn:
        stuck = job_store.create(conn, "interrupted.csv")
        job_store.mark_running(conn, stuck.job_id)
        finished = job_store.create(conn, "finished.csv")
        job_store.mark_done(conn, finished.job_id, result_type=job_store.ResultType.RUNBOOK,
                            result_path="somewhere.json")

    serve.create_app()  # a new server boots

    with db.connection() as conn:
        assert job_store.get(conn, stuck.job_id).status is JobStatus.FAILED
        assert job_store.get(conn, finished.job_id).status is JobStatus.DONE


def test_an_orphaned_run_stops_polling_and_says_what_to_do(workspace):
    """Left alone the status page polls a job nothing will ever finish."""
    with db.connection() as conn:
        stuck = job_store.create(conn, "interrupted.csv")
        job_store.mark_running(conn, stuck.job_id)

    fresh = TestClient(serve.create_app())
    response = fresh.get(f"/jobs/{stuck.job_id}")

    assert response.status_code == 200
    assert "hx-trigger" not in response.text
    assert "Upload the sample again" in response.text


def test_empty_upload_fails_the_job_with_a_reason(client, tmp_path):
    empty = tmp_path / "empty.csv"
    empty.write_bytes(b"")

    job_id = _upload(client, empty).headers["location"].rsplit("/", 1)[-1]

    with db.connection() as conn:
        job = job_store.get(conn, job_id)
    assert job.status is JobStatus.FAILED
    assert "empty" in job.error


def test_unparsable_upload_fails_the_job_without_killing_the_server(client, tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{ not json at all", encoding="utf-8")

    job_id = _upload(client, broken).headers["location"].rsplit("/", 1)[-1]

    with db.connection() as conn:
        job = job_store.get(conn, job_id)
    assert job.status is JobStatus.FAILED
    assert job.error
    # The server is still serving.
    assert client.get("/").status_code == 200


def test_history_lists_finished_runs(client):
    _seed_taxonomy()
    _upload(client, CLOUDFLARE)

    response = client.get("/history")

    assert "cloudflare_waf_firewall_events.csv" in response.text
    assert "candidates found" in response.text
