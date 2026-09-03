# Business model

> **Status: pre-revenue prototype.** FixNex has no customers, no users and no revenue.
> Every figure below is an illustrative model, labelled as such — none of it is measured.
> This document sets out who would pay for this, why, and what would have to be true.

---

## What we sell

A security assessment platform that manages the whole engagement — scope, scanning,
verification, evidence, risk, remediation, retest and the client report — instead of
leaving it spread across five disconnected tools and a spreadsheet.

We do not build scanners. We orchestrate them, normalize what they produce, and own
everything that happens to a finding afterwards.

---

## The problem, stated as a cost

A penetration test is sold as a deliverable: a report. But the work behind it is scattered.

- Recon in one tool, scanning in another, verification tracked by hand
- Evidence in a folder, with no integrity guarantee
- Risk scored manually and inconsistently between testers
- The report assembled at the end, by hand, from all of the above

Industry practitioners commonly put **20–40% of engagement hours** into reporting and
administration rather than testing. For a consultancy that bills by the day, that is
margin lost to clerical work — and it is the least enjoyable part of the job, so it is
also a retention problem.

The pitch is not "find more bugs." It is **"bill the same engagement with fewer
non-testing hours, and produce a defensible report at the end."**

---

## Who buys

The data model is engagement-shaped — assessments carry a `client_name`, an
`engagement_type`, start and end dates, a methodology and a scope authorization. That is
a firm doing work *for someone else*, and it defines the primary customer.

### Primary — boutique security consultancies (3–20 testers)

Too small for enterprise tooling budgets, too large to keep coordinating in spreadsheets.
They feel the reporting tax on every engagement and they carry the liability of scanning
the wrong host. They buy tools with a company card, not a twelve-month procurement cycle.

### Secondary — internal application security teams

Mid-size companies running recurring internal assessments. Same lifecycle, "client" is an
internal business unit. Longer sales cycle, larger seat count, stickier once adopted.

### Tertiary — universities and training programmes

The audit trail, role separation and scope enforcement map onto supervised student work.
Low revenue, high advocacy — students who learn on a platform bring it to their employers.

---

## Where we fit

Honest positioning against the real alternatives:

| Alternative | What it is | Where it leaves a gap |
|---|---|---|
| **Spreadsheets + Word** | What most small firms actually use | No correlation, no evidence integrity, no audit trail, report written by hand |
| **DefectDojo** | Mature open-source vulnerability management | Strong at ingesting scanner output; weaker on engagement workflow, scope authorization and client deliverables |
| **PlexTrac** | Commercial market leader, report-centric | Priced for larger firms; heavier to adopt |
| **AttackForge / Dradis / Faraday** | Pentest management platforms | Closest direct competitors; differentiation must be earned, not asserted |

This is a real market with real incumbents. "There is nothing like this" would be false.

### What is genuinely differentiated

1. **Scope is an enforced gate, not a note.** An out-of-scope target is refused at the API,
   and the refusal is written to the audit log. For a consultancy, scanning outside
   authorization is a legal and reputational event — this is control evidence, not a
   feature.
2. **Provenance is never faked.** Every finding is marked `REAL_SCAN`, `IMPORTED`,
   `MANUAL` or `SEEDED_DEMO`, in the UI, the API and the report. A derived CVSS vector is
   labelled `estimated` rather than presented as authoritative.
3. **Contextual risk is separated from CVSS.** CVSS describes the vulnerability; the
   platform score describes what it means for this asset, and is never presented as an
   official CVSS rating.
4. **Every external dependency is optional.** Missing scanners degrade to built-in
   adapters and say so. The product works on day one without a procurement exercise.

Points 1 and 2 are the defensible ones. They are trust properties, and trust is what a
firm is actually selling to its own clients.

---

## Model: open-core with hosted tiers

Security buyers distrust closed boxes handling their findings, and the fastest path to
adoption in this market is source availability. Revenue comes from hosting, collaboration
and compliance features rather than from the core lifecycle.

| Tier | Price *(illustrative)* | For | Includes |
|---|---|---|---|
| **Community** | Free, self-hosted | Individuals, students, evaluation | Full assessment lifecycle, scanners, reports, audit trail |
| **Team** | ~$39 / user / month | Small consultancies | Hosted, SSO, backups, evidence retention, support |
| **Firm** | ~$79 / user / month | Established consultancies | Client-facing portals, white-labelled reports, compliance packs (NIST/ISO), longer audit retention |
| **Enterprise** | Custom | Regulated / on-prem | Self-hosted with support, extended retention, procurement and security review |

Deliberately **not** priced per scan or per finding. Usage pricing punishes thorough
testing, which is the opposite of the incentive this product should create.

### Illustrative economics

A six-person consultancy on the Firm tier is roughly **$5,700 per year**. If the platform
saves each tester four hours of reporting per engagement, at a $150/hour billable rate
across twenty engagements a year, that is well above the subscription cost — the ROI
argument is hours, not features.

*These are modelled numbers used to size the opportunity. They are not measured, and the
billable-rate and hours-saved assumptions are the first things a real pilot must test.*

---

## Go to market

1. **Open source as the top of funnel.** The self-hosted tier is the marketing. Practitioners
   evaluate tools by running them, not by booking demos.
2. **Land on the report.** The wedge is the deliverable — the thing the firm actually sells.
   A firm that produces one report through FixNex has already moved its workflow.
3. **Expand by seat, then by feature.** Teams grow into client portals, white-labelling and
   compliance mapping.
4. **Community credibility.** Scanner adapters are a contribution surface: each new adapter
   makes the platform more useful and is written by someone who now knows the codebase.

---

## Risks, stated plainly

- **Crowded category.** PlexTrac, AttackForge, Dradis and Faraday are established. Being
  newer is not an advantage on its own.
- **A free incumbent.** DefectDojo is capable and costs nothing. Any paid tier must be
  worth more than "it is nicer to use."
- **Trust barrier.** Firms are cautious about where client findings live. Self-hosting
  answers this, but self-hosting is also the tier that generates no revenue.
- **Scanner vendors moving up-stack.** If a scanner vendor bundles adequate workflow, the
  orchestration layer compresses.
- **Open-core boundary.** Put too much behind the paywall and the community tier dies; too
  little and nobody upgrades. This line is the hardest ongoing product decision.

## What would have to be true

1. Consultancies will move reporting into a new tool — the highest-risk assumption, and the
   one to test first with five pilot firms.
2. Time saved is large and visible enough to justify per-seat pricing.
3. Scope enforcement and provenance are valued as risk controls, not dismissed as friction.
4. The open-core boundary can be drawn so the free tier is genuinely useful and the paid
   tier is genuinely worth buying.

## Honest current state

A working prototype with the full lifecycle implemented, five scanner integrations,
graceful degradation throughout, and 354 passing backend tests. No pilot customers, no
revenue, and none of the assumptions above validated against a paying firm.

The next step is not more features. It is putting this in front of five consultancies and
finding out whether assumption 1 survives contact.
