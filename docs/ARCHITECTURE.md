# Architecture

How FixNex is put together, and why.

## Layering

```
  api/routes/     thin HTTP: validate, authorize, delegate. No business logic.
       │
  services/       all business logic; owns transactions and audit writes
       │
  models/         SQLAlchemy ORM; the schema is the contract
       │
  PostgreSQL      single source of truth for application data
```

Supporting packages sit beside these rather than inside them:

| Package | Responsibility |
|---|---|
| `core/` | Configuration, the permission matrix, exceptions, middleware, logging |
| `scanners/` | The `ScannerAdapter` contract and one module per integrated tool |
| `storage/` | Object storage abstraction (MinIO / local filesystem) |
| `workers/` | Celery application and the task-runner abstraction |
| `reports/` | Report context building and format renderers |
| `security/` | Password hashing, JWT issuing/verification, rate limiting |

**Rule:** a route never imports a scanner, and a scanner never imports a model. The
`services/` layer is the only place the two meet.

## The scanner adapter contract

The single most important abstraction. Everything a tool produces is converted into
`NormalizedFinding` before it touches the rest of the system:

```python
@dataclass
class NormalizedFinding:
    title: str
    severity: str          # canonical five-level scale
    target: str
    endpoint: str | None
    source: str            # adapter name
    cwe: str | None
    cve: list[str]
    cvss: float | None
    cvss_vector: str | None
    evidence: str | None
    confidence: float      # 0.0 – 1.0
    ...
```

Because correlation, scoring, risk, remediation and reporting only ever see this shape,
adding a tool is additive: write an adapter, register it, done.

Adapters also declare **availability**, which is what makes the platform survive a
machine where nothing is installed:

```python
def availability(self) -> ScannerAvailability:
    path = which(settings.NUCLEI_PATH)
    if not path:
        return ScannerAvailability(False, "The `nuclei` binary was not found on PATH…")
    return ScannerAvailability(True, f"Found at {path}", tool_version(...))
```

## Severity normalization

Tools disagree about vocabulary. ZAP emits numeric risk codes, Nuclei emits
`info|low|medium|high|critical`, others emit `warning` or `moderate`. All of it is mapped
onto one scale before it reaches the finding system (`scanners/base.py`), so a filter for
"High" means the same thing regardless of which tool reported it.

## Correlation and deduplication

`services/correlation.py` derives a stable key per finding:

```
correlation_key = sha256(
    target | normalized_endpoint | vulnerability_identity | parameter
)
```

`vulnerability_identity` uses the strongest available signal:

1. a shared **CVE** — the most reliable,
2. otherwise a shared **CWE** (inferred from the title when the tool supplies none),
3. otherwise a **normalized title** with version numbers and filler words removed.

The endpoint is reduced to host + path, so `?q=1` and `?q=2` are the same issue. Findings
sharing a key are merged: highest severity wins, the richest description wins, CVE lists
union, and confidence rises because independent tools agreed.

## Contextual risk

Kept deliberately separate from CVSS. CVSS describes the vulnerability; contextual risk
describes what it means for *this* asset.

```
points   = criticality + sensitivity + exposure + exploit + verification
headroom = (10 - base)/10  when points ≥ 0
           base/10         when points < 0
risk     = clamp(base + points × headroom, 0, 10)
```

Scaling by headroom is what keeps the score useful. A multiplicative model was tried
first and saturated: with a 1.5× modifier every finding on a high-criticality
internet-facing asset hit the 10.0 ceiling, so a missing security header ranked equal to
an unauthenticated SQL injection. The headroom model preserves ordering, never pins to
the ceiling, and lets context reduce a score as well as raise it.

Every score carries its factor-by-factor explanation and an explicit disclaimer that it
is a platform score, not an official CVSS rating.

## Background execution

Long scans must never block an API request, but requiring Redis to demo the product is a
poor trade. `workers/runner.py` abstracts this:

```
TASK_RUNNER=auto  →  broker reachable ?  CeleryTaskRunner : ThreadTaskRunner
```

Both satisfy the same interface, so `services/scanning.py` is unaware of which is in use.
The scan job records which runner executed it.

## Live progress

The WebSocket handler reads scan state from PostgreSQL on a short interval and pushes
changes to the client. This deliberately avoids an in-memory pub/sub, because the Celery
worker is a *different process* from the API — a memory-based bus would silently work in
thread mode and silently fail in Celery mode. Reading committed state is correct under
both. The client falls back to polling if the socket cannot be established.

## Evidence integrity

PostgreSQL stores only metadata; bytes live in object storage under a
traversal-safe key. On upload the SHA-256 hash is computed and stored, and
`GET /api/evidence/{id}/verify` re-hashes the stored object to prove it has not changed.

Evidence is never overwritten. Replacing a file creates a new version that supersedes the
previous one, and the superseded record is retained for chain of custody.

## Audit immutability

Immutability here is structural rather than a convention:

- `services/audit.py` exposes `record()` and read helpers, and no mutation function.
- No route maps to an audit update or delete.
- `Permission` contains no `audit:delete` member, so no role can hold it.

A test asserts each of these.
