# Demo script

A 5–10 minute walkthrough covering the complete lifecycle. All accounts use the password
**`DemoPass123!`**.

---

### 1 · Dashboard  (`lead@fixnex.io`) — 45s

Sign in as the Security Lead.

> "Everything a security team does across five disconnected tools, in one place."

Point out: severity distribution, **contextual risk** (labelled as distinct from CVSS),
the impact/likelihood heat map, remediation progress, SLA counters, and the audit feed.

### 2 · Authorized scope — 60s

**Assessments → College Portal Security Assessment → Scope**

> "This is the control that stops the platform being an arbitrary scanner."

- A wildcard inclusion, and an explicit **exclusion** for the third-party payment gateway.
- Use the **scope checker**: an in-scope host passes; `example.org` is refused.

### 3 · Scope is enforced, not advisory — 45s

**Targets → Add target →** enter an out-of-scope host, tick the authorization box, submit.

> "Rejected — and note this attempt is now in the audit log."

Then add a legitimate in-scope target. Show the live green in-scope confirmation and the
mandatory authorization statement.

### 4 · Run a scan — 90s

**New scan → Standard.**

> "One scan, several tools. Anything not installed is skipped, not fatal."

Show the scanner availability list, start it, and watch live progress: percentage,
current operation, per-scanner status, and **raw results vs. deduplicated findings**.

> "ZAP and Nuclei both reported the same SQL injection. The correlation engine merged them
> into one finding with two sources."

### 5 · The finding — 90s

**Findings → SQL injection in student results lookup**

- Two score rings: **CVSS 9.8** base, and the separate **contextual risk**.
- Open *How was this calculated?* — the factor-by-factor explanation.

> "CVSS describes the vulnerability. Contextual risk describes what it means for this
> asset — and we never present it as an official CVSS rating."

- CWE-89 linked to MITRE; CVE enrichment from NVD where applicable.

### 6 · Verification and false positives — 60s

**Verify → False positive** on the feedback-form XSS.

> "A justification is mandatory, and the finding is never deleted — it stays for audit."

Reopen it to show the retained justification and that contextual risk dropped to zero.

### 7 · Evidence — 45s

**Evidence tab.** Upload a file.

> "SHA-256 recorded at upload."

Click **Verify integrity** → proves the stored bytes are unchanged. Annotate a screenshot.

### 8 · Assign for remediation — 30s

**Triage → P1 → Assign** to the developer. The SLA clock starts.

### 9 · The developer's view — 60s

Sign in as `developer@fixnex.io`.

> "Same platform, completely different surface."

- Five sidebar items; no Scans, Reports, Audit or Administration.
- Only their assigned findings.
- Update progress → **Mark ready for retest**.

> "They cannot set Resolved, and cannot touch CVSS. Only a passing retest closes a finding."

### 10 · Retest and closure — 45s

Sign in as `engineer@fixnex.io` → open the finding → **Retest → Pass**.

> "Closed. A failing retest would have reopened remediation instead — and either way the
> history is preserved."

**Activity tab** — the full timeline from discovery to closure.

### 11 · Audit and report — 45s

**Audit Logs** — every action, with actor, role, IP and timestamp.

> "Append-only. There is no API route and no role permission that can edit or delete
> these."

**Reports → Generate → PDF** → open the downloaded report.

### 12 · Close — 20s

**Administration → System Health**

> "Nmap, Nuclei and ZAP are integrated but optional — FixNex ships four built-in
> scanners so it produces real findings anywhere. Adding a sixth tool means writing one
> adapter; nothing downstream changes."

---

## If something goes wrong

| Problem | Response |
|---|---|
| A scanner shows unavailable | That is the intended design — say so and continue |
| The live scan is slow | Open a previously completed scan instead |
| Network enrichment fails | CVE data degrades to link-only; the finding is unaffected |
| PDF generation is slow | Generate JSON or CSV, which are instant |
