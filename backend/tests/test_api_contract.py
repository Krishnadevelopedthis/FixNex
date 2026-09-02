"""API shape contracts.

Three separate screens were unmounted in production-like use by the same bug:
a collection endpoint returned a bare JSON array while the client expected a
paginated object. An empty array is truthy in JavaScript, so `data.items.length`
threw and React tore down the whole tree.

These tests pin the contract for every collection endpoint at once, so adding a
new one that returns a bare list fails here rather than in the browser.
"""
from __future__ import annotations

import pytest

from app.core.permissions import Role
from app.main import app as fastapi_app

PAGE_KEYS = {"items", "total", "page", "page_size", "pages"}

# Endpoints that return a full page object.
PAGINATED = [
    "/api/assessments",
    "/api/assets",
    "/api/targets",
    "/api/scans",
    "/api/findings",
    "/api/reports",
    "/api/audit-logs",
    "/api/remediation",
]

# Endpoints that intentionally return a bare array: small, bounded, unpaged
# reference data the UI renders in full.
BARE_LIST = [
    "/api/users",
    "/api/roles",
    "/api/scans/scanners",
    "/api/scans/profiles",
    "/api/scans/import/tools",
    "/api/audit-logs/actions",
]


@pytest.mark.parametrize("path", PAGINATED)
def test_collection_endpoints_return_a_page(client, auth, path):
    response = client.get(path, headers=auth(Role.ADMIN))
    assert response.status_code == 200, f"{path} -> {response.status_code} {response.text[:120]}"
    body = response.json()
    assert isinstance(body, dict), (
        f"{path} returned a bare list; the client expects a page object. "
        "An empty array is truthy in JS, so `.items.length` throws and unmounts the screen."
    )
    assert PAGE_KEYS <= set(body), f"{path} is missing page keys: {PAGE_KEYS - set(body)}"
    assert isinstance(body["items"], list)


@pytest.mark.parametrize("path", PAGINATED)
def test_paginated_endpoints_honour_page_size(client, auth, path):
    body = client.get(path, headers=auth(Role.ADMIN), params={"page_size": 1}).json()
    assert len(body["items"]) <= 1
    assert body["page_size"] == 1


@pytest.mark.parametrize("path", PAGINATED)
def test_paginated_endpoints_are_page_shaped_when_empty(client, auth, path):
    """The empty case is exactly the one that used to crash the UI."""
    body = client.get(path, headers=auth(Role.ADMIN), params={"page": 9999}).json()
    assert body["items"] == []
    assert PAGE_KEYS <= set(body)


@pytest.mark.parametrize("path", BARE_LIST)
def test_reference_endpoints_return_a_bare_list(client, auth, path):
    """These are deliberately unpaged; the test documents that choice."""
    response = client.get(path, headers=auth(Role.ADMIN))
    assert response.status_code == 200, path
    assert isinstance(response.json(), list), path


def test_every_registered_collection_route_is_covered():
    """Fail when a new GET collection route appears that no test above pins.

    Without this, the next endpoint added with a bare-list response reaches the
    browser before anyone notices.
    """
    known = set(PAGINATED) | set(BARE_LIST)
    # Routes that return a single object or a file, not a collection.
    exempt_suffixes = ("/health", "/me", "/dashboard")

    uncovered = []
    for route in fastapi_app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set()) or set()
        if "GET" not in methods or not path.startswith("/api"):
            continue
        if "{" in path or path in known or path.endswith(exempt_suffixes):
            continue
        response_field = getattr(route, "response_field", None)
        annotation = getattr(response_field, "type_", None) if response_field else None
        origin = getattr(annotation, "__origin__", None)
        # A list[...] response model on a collection path is the risky shape.
        if origin is list:
            uncovered.append(path)

    assert not uncovered, (
        "These GET routes return a bare list but are not pinned by a contract test above. "
        f"Add them to PAGINATED (and paginate them) or to BARE_LIST: {sorted(uncovered)}"
    )


# ---------------------------------------------------------------- pagination
@pytest.mark.parametrize("path", PAGINATED)
def test_absurd_page_is_rejected_not_a_server_error(client, auth, path):
    """Regression: an unbounded page overflowed the SQL OFFSET.

    `OFFSET = (page - 1) * page_size` exceeded a bigint and Postgres raised
    NumericValueOutOfRange, which surfaced to the caller as a 500 rather than a
    validation error.
    """
    response = client.get(path, headers=auth(Role.ADMIN), params={"page": 99999999999999999999})
    assert response.status_code == 422, f"{path} -> {response.status_code}"


@pytest.mark.parametrize("path", PAGINATED)
def test_page_upper_bound_is_enforced(client, auth, path):
    from app.api.deps import MAX_PAGE

    assert client.get(path, headers=auth(Role.ADMIN), params={"page": MAX_PAGE}).status_code == 200
    assert client.get(path, headers=auth(Role.ADMIN), params={"page": MAX_PAGE + 1}).status_code == 422


def test_unknown_sort_field_falls_back_instead_of_failing(client, auth):
    """`sort_by` is a whitelist lookup with a default, not raw SQL."""
    response = client.get(
        "/api/findings", headers=auth(Role.ADMIN),
        params={"sort_by": "; DROP TABLE findings; --"},
    )
    assert response.status_code == 200
    assert "items" in response.json()
