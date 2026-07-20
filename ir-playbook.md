# Incident Response Playbook — Juice Shop Web Attack Detection

This playbook documents a simulated SOC Tier 1 response process, based on the attacks detected in this lab. It follows the standard Detection → Triage → Escalation → Remediation → Lessons Learned flow.

---

## 1. Detection

**Source:** Splunk Alert — "Juice Shop Attack Detection Alert"
**Trigger:** Search returns ≥1 event matching known attack signatures (SQLi, XSS, path traversal patterns) in `index=juiceshop_lab`

Four events were detected in a single monitoring window:

| Time | Attack Type | Status Code |
|---|---|---|
| 2026-07-21 01:53:40 | SQLi_LOGIN_BYPASS | 200 |
| 2026-07-21 01:53:40 | XSS_SEARCH | 200 |
| 2026-07-21 01:53:40 | PATH_TRAVERSAL | 200 |
| 2026-07-21 01:53:40 | UNION_SQLI | 500 |

---

## 2. Triage

Each event was reviewed individually rather than treated with blanket severity — reflecting real SOC practice of confirming impact before escalating.

| Event | Triage Outcome | Reasoning |
|---|---|---|
| SQLi_LOGIN_BYPASS | **Critical — Confirmed** | Response body contained a valid, signed JWT with `"role":"admin"` — attacker obtained an authenticated admin session with no valid credentials. |
| UNION_SQLI | **High — Confirmed** | HTTP 500 with `SQLITE_ERROR: near "UNION"` — confirms the query reached the database layer unsanitized. Discloses backend DB type (SQLite). |
| XSS_SEARCH | **Medium — Needs further verification** | Server accepted the payload and returned 200, but response body did not reflect executable script content in this response. Requires browser-based confirmation to verify DOM execution. |
| PATH_TRAVERSAL | **False Positive** | Request returned the application's own static `index.html`, not an OS-level file. No evidence the traversal actually escaped the web root. |

---

## 3. Escalation

Per the triage outcomes, escalation to L2 SOC would be warranted for:

- **SQLi_LOGIN_BYPASS** — immediate escalation. Confirmed authentication bypass with admin-level access is a critical finding requiring containment.
- **UNION_SQLI** — escalation recommended. Confirmed SQL injection with information disclosure (DB error message) warrants deeper investigation into the extent of injectable parameters.

Not escalated (handled at Tier 1, documented and closed):
- **XSS_SEARCH** — logged for follow-up manual verification; not escalated until impact is confirmed.
- **PATH_TRAVERSAL** — closed as false positive after review.

---

## 4. Remediation Recommendations

| Vulnerability | Recommendation |
|---|---|
| SQL Injection (login & search) | Use parameterized queries / prepared statements instead of string concatenation. Apply input validation and an allow-list for expected input formats. |
| Reflected XSS | Apply context-aware output encoding on all user-supplied input before rendering. Add a Content-Security-Policy (CSP) header to reduce impact of any missed cases. |
| General | Ensure verbose SQL error messages are not returned to the client in production — use generic error responses and log details server-side only. |

---

## 5. Lessons Learned

- Application-level debug logs were insufficient for detection; capturing full request/response detail at the point of attack (via `curl -v`) produced far more actionable evidence than the container's default log output.
- Automated severity classification (via SPL `eval case()`) demonstrates how a SOC Tier 1 analyst can triage multiple alerts efficiently rather than manually reviewing each one from scratch.
- Distinguishing a true positive (UNION SQLi, SQLi login bypass) from a false positive (path traversal) is as important as detecting the events in the first place — over-alerting erodes trust in a detection pipeline.
- Future improvement: correlate with network-layer evidence (e.g., a packet capture) to strengthen the XSS finding, and integrate with a ticketing system to simulate a full Tier 1 → Tier 2 handoff.
