"""Evidence upload, integrity and chain of custody."""
from __future__ import annotations

import hashlib

import pytest

from app.core.exceptions import StorageError
from app.core.permissions import Role
from app.services.evidence import sanitize_filename
from app.storage.local import LocalStorage


def upload(client, headers, finding_id, name="proof.txt", content=b"evidence body", ctype="text/plain",
           description="Captured during testing"):
    return client.post(
        f"/api/findings/{finding_id}/evidence",
        headers=headers,
        files={"file": (name, content, ctype)},
        data={"description": description},
    )


def test_upload_records_hash_uploader_and_version(client, auth, finding):
    content = b"GET / HTTP/1.1\r\nHost: app.local\r\n\r\nHTTP/1.1 200 OK"
    response = upload(client, auth(Role.SECURITY_ENGINEER), finding.id, content=content)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["file_hash"] == hashlib.sha256(content).hexdigest()
    assert body["version"] == 1
    assert body["is_current"] is True
    assert body["uploaded_by"]["role"] == Role.SECURITY_ENGINEER
    assert body["created_at"]


def test_integrity_check_confirms_the_stored_bytes(client, auth, finding):
    evidence_id = upload(client, auth(Role.ANALYST), finding.id).json()["id"]
    response = client.get(f"/api/evidence/{evidence_id}/verify", headers=auth(Role.ANALYST))
    assert response.status_code == 200
    assert response.json()["integrity_verified"] is True


def test_evidence_can_be_downloaded_intact(client, auth, finding):
    content = b"exact bytes \x00\x01 preserved"
    evidence_id = upload(client, auth(Role.ANALYST), finding.id, content=content,
                         name="raw.txt").json()["id"]
    response = client.get(f"/api/evidence/{evidence_id}/download", headers=auth(Role.ANALYST))
    assert response.status_code == 200
    assert response.content == content


def test_new_version_supersedes_rather_than_overwrites(client, auth, finding):
    first = upload(client, auth(Role.SECURITY_ENGINEER), finding.id, content=b"v1").json()
    second = client.post(
        f"/api/findings/{finding.id}/evidence",
        headers=auth(Role.SECURITY_ENGINEER),
        files={"file": ("proof.txt", b"v2", "text/plain")},
        data={"description": "Corrected capture", "supersedes_id": str(first["id"])},
    )
    assert second.status_code == 201, second.text
    body = second.json()
    assert body["version"] == 2
    assert body["supersedes_id"] == first["id"]

    # The original is retained for chain of custody, just no longer current.
    original = client.get(f"/api/evidence/{first['id']}", headers=auth(Role.SECURITY_ENGINEER))
    assert original.status_code == 200
    assert original.json()["is_current"] is False


def test_viewer_cannot_upload_evidence(client, auth, finding):
    assert upload(client, auth(Role.VIEWER), finding.id).status_code == 403


def test_developer_cannot_delete_evidence(client, auth, finding):
    evidence_id = upload(client, auth(Role.SECURITY_ENGINEER), finding.id).json()["id"]
    response = client.delete(f"/api/evidence/{evidence_id}", headers=auth(Role.DEVELOPER))
    assert response.status_code == 403


def test_disallowed_content_type_is_rejected(client, auth, finding):
    response = upload(
        client, auth(Role.SECURITY_ENGINEER), finding.id,
        name="payload.exe", content=b"MZ\x90\x00", ctype="application/x-msdownload",
    )
    assert response.status_code in (400, 415, 422)


def test_oversized_upload_is_rejected(client, auth, finding, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "MAX_UPLOAD_BYTES", 64)
    response = upload(client, auth(Role.SECURITY_ENGINEER), finding.id, content=b"x" * 500)
    assert response.status_code in (400, 413, 422)


@pytest.mark.parametrize(
    "dangerous,expected_safe",
    [
        ("../../../etc/passwd", "passwd"),
        ("..\\..\\windows\\system32\\config", "config"),
        ("/absolute/path/file.txt", "file.txt"),
        ("normal-name.png", "normal-name.png"),
    ],
)
def test_filenames_are_sanitised(dangerous, expected_safe):
    cleaned = sanitize_filename(dangerous)
    assert "/" not in cleaned and "\\" not in cleaned
    assert ".." not in cleaned
    assert cleaned.endswith(expected_safe)


def test_local_storage_refuses_path_traversal(tmp_path):
    store = LocalStorage(str(tmp_path))
    with pytest.raises(StorageError):
        store.put("../escaped.txt", b"nope")
    with pytest.raises(StorageError):
        store.put("/etc/passwd", b"nope")


def test_local_storage_round_trip(tmp_path):
    store = LocalStorage(str(tmp_path))
    store.put("findings/1/proof.txt", b"hello")
    assert store.exists("findings/1/proof.txt")
    assert store.get("findings/1/proof.txt") == b"hello"
    store.delete("findings/1/proof.txt")
    assert not store.exists("findings/1/proof.txt")
