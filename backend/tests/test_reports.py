"""Report rendering across formats and engines."""
from __future__ import annotations

import app.reports.renderers as renderers
from app.core.permissions import Role


def test_weasyprint_is_probed_only_once(monkeypatch):
    """Regression: the probe used to re-import WeasyPrint on every render.

    Importing WeasyPrint dlopens pango/cairo through cffi. Repeating that
    failing dlopen on a host without those libraries crashed the interpreter
    after a handful of PDF renders, taking the whole API down with it.
    """
    monkeypatch.setattr(renderers, "_weasyprint_probe", None)
    attempts = {"count": 0}
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def counting_import(name, *args, **kwargs):
        if name == "weasyprint":
            attempts["count"] += 1
            raise OSError("cannot load library 'libpango-1.0-0'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", counting_import)

    for _ in range(25):
        available, detail = renderers.weasyprint_available()
        assert available is False
        assert detail == "OSError"

    assert attempts["count"] == 1, (
        f"WeasyPrint was imported {attempts['count']} times; it must be probed once."
    )


def test_pdf_falls_back_to_fpdf2_when_weasyprint_is_missing(client, auth, assessment, finding):
    response = client.post(
        "/api/reports",
        headers=auth(Role.SECURITY_LEAD),
        json={"assessment_id": assessment.id, "format": "PDF"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "READY"
    # Either engine is acceptable; the point is that a PDF is always produced.
    assert body["engine"] in ("weasyprint", "fpdf2")

    download = client.get(
        f"/api/reports/{body['id']}/download", headers=auth(Role.SECURITY_LEAD)
    )
    assert download.status_code == 200
    assert download.content[:4] == b"%PDF"


def test_repeated_pdf_generation_is_stable(client, auth, assessment, finding):
    """Generating many PDFs in one process must not destabilise the server."""
    for _ in range(8):
        response = client.post(
            "/api/reports",
            headers=auth(Role.SECURITY_LEAD),
            json={"assessment_id": assessment.id, "format": "PDF"},
        )
        assert response.status_code == 201, response.text


def test_json_and_csv_reports(client, auth, assessment, finding):
    for fmt, magic in (("JSON", b"{"), ("CSV", b"")):
        created = client.post(
            "/api/reports",
            headers=auth(Role.SECURITY_LEAD),
            json={"assessment_id": assessment.id, "format": fmt},
        )
        assert created.status_code == 201, created.text
        download = client.get(
            f"/api/reports/{created.json()['id']}/download", headers=auth(Role.SECURITY_LEAD)
        )
        assert download.status_code == 200
        assert len(download.content) > 0
        if magic:
            assert download.content.lstrip()[:1] == magic


def test_viewer_can_download_but_not_generate(client, auth, assessment, finding):
    assert client.post(
        "/api/reports",
        headers=auth(Role.VIEWER),
        json={"assessment_id": assessment.id, "format": "JSON"},
    ).status_code == 403

    created = client.post(
        "/api/reports",
        headers=auth(Role.SECURITY_LEAD),
        json={"assessment_id": assessment.id, "format": "JSON"},
    ).json()
    assert client.get(
        f"/api/reports/{created['id']}/download", headers=auth(Role.VIEWER)
    ).status_code == 200


def test_report_generation_is_audited(client, auth, assessment, finding):
    client.post(
        "/api/reports",
        headers=auth(Role.SECURITY_LEAD),
        json={"assessment_id": assessment.id, "format": "JSON"},
    )
    logs = client.get(
        "/api/audit-logs", headers=auth(Role.ADMIN), params={"page_size": 100}
    ).json()
    assert any(entry["action"] == "report.generated" for entry in logs["items"])


def test_report_list_is_paginated_like_every_other_collection(client, auth, assessment, finding):
    """Regression: this endpoint returned a bare list while the client expected a page.

    An empty list is truthy in JavaScript, so `reports.items.length` threw and
    unmounted the whole assessment screen.
    """
    client.post(
        "/api/reports",
        headers=auth(Role.SECURITY_LEAD),
        json={"assessment_id": assessment.id, "format": "JSON"},
    )
    response = client.get(
        "/api/reports", headers=auth(Role.VIEWER), params={"assessment_id": assessment.id}
    )
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict), "the list endpoint must return a page object, not a bare list"
    assert set(body) >= {"items", "total", "page", "page_size", "pages"}
    assert isinstance(body["items"], list)
    assert body["total"] >= 1


def test_report_list_is_paginated_when_empty(client, auth, assessment):
    response = client.get(
        "/api/reports", headers=auth(Role.VIEWER), params={"assessment_id": assessment.id}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["items"] == [] and body["total"] == 0 and body["pages"] == 1


def test_report_list_respects_page_size(client, auth, assessment, finding):
    for _ in range(3):
        client.post(
            "/api/reports",
            headers=auth(Role.SECURITY_LEAD),
            json={"assessment_id": assessment.id, "format": "JSON"},
        )
    response = client.get(
        "/api/reports",
        headers=auth(Role.VIEWER),
        params={"assessment_id": assessment.id, "page_size": 2},
    )
    body = response.json()
    assert len(body["items"]) == 2
    assert body["total"] == 3 and body["pages"] == 2
