# SPL Queries — Juice Shop Detection Lab

Index used: `juiceshop_lab`
Source type: `juiceshop_lab`
Source file: `attack_traffic.log`

---

## 1. Raw event check (verify ingestion)

```spl
index="juiceshop_lab"
```

Confirms all 4 attack events were ingested and parsed as separate events.

---

## 2. Basic summary table

```spl
index="juiceshop_lab"
| table _time, ATTACK_TYPE, host, source
| sort -_time
```

---

## 3. Extract HTTP status code per attack

```spl
index="juiceshop_lab"
| rex field=_raw "(?m)^<\sHTTP/1\.1\s(?<status_code>\d+)"
| table _time, ATTACK_TYPE, status_code
| sort -_time
```

Result:

| Attack Type | Status Code |
|---|---|
| PATH_TRAVERSAL | 200 |
| XSS_SEARCH | 200 |
| SQLi_LOGIN_BYPASS | 200 |
| UNION_SQLI | 500 |

---

## 4. Severity classification (triage logic)

```spl
index="juiceshop_lab" ATTACK_TYPE=*
| rex field=_raw "(?m)^<\sHTTP/1\.1\s(?<status_code>\d+)"
| eval severity=case(
    status_code=500, "High - Possible SQL Injection Confirmed",
    ATTACK_TYPE="SQLi_LOGIN_BYPASS", "Critical - Auth Bypass",
    1=1, "Medium - Investigate"
  )
| table _time, ATTACK_TYPE, status_code, severity
```

This query simulates SOC Tier 1 triage: automatically tagging each detected event with a severity level based on attack type and server response, rather than treating every alert equally.

---

## 5. Alert search (saved as scheduled alert)

Same query as #4, saved as a Splunk Alert:

- **Name:** Juice Shop Attack Detection Alert
- **Trigger condition:** Number of Results > 0
- **Alert type:** Scheduled (cron)
- **Action:** Add to Triggered Alerts

---

## Notes on field extraction

- `ATTACK_TYPE` was automatically extracted by Splunk as an "Interesting Field" from the `ATTACK_TYPE=` marker embedded in each log block header — no manual `rex` needed for this field.
- `status_code` required a manual `rex` extraction since the HTTP response line (`< HTTP/1.1 200 OK`) is part of the curl verbose output, not a labeled field.
