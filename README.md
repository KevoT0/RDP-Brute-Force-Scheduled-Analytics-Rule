# Detection Engineering: RDP Brute-Force Scheduled Analytics Rule

**Lab environment:** Microsoft Sentinel Training Lab dataset (`SecurityEvent`)
**SC-200 domain:** Configure protections and detections
**Detection surface:** Microsoft Sentinel (Defender portal) · KQL · Scheduled Analytics Rule

---

## Summary

Building on the manual brute-force hunt from a previous lab, I converted a one-time hunting query into a **live scheduled analytics rule** that runs continuously and automatically raises an incident when an RDP brute-force spike is detected. This lab covers the jump from *hunting* (an analyst running a query) to *detection engineering* (the platform detecting on its own), including query tuning for detection, entity mapping, scheduling, thresholds, and — importantly — correctly interpreting why the rule stays quiet against historical lab data.

---

## Environment note

Performed in a lab tenant on the Sentinel Training Lab dataset. The dataset is historical and does not regenerate, which is directly relevant to how the rule behaves (see *Validation* below). The rule logic transfers unchanged to a production environment with live telemetry.

---

## Objective

Take the manual hunt — *"which accounts have a high number of failed logons?"* — and operationalise it so that:
- it runs automatically on a schedule,
- it fires only on a meaningful burst, not on ordinary login noise,
- it produces an investigable incident with the Account and Host attached as entities.

---

## From hunt to detection: tuning the query

The original hunt counted all failed logons across the full dataset. A detection rule instead runs on a schedule over a recent window, so the query was tuned:

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogin = count() by Account, Computer
| where FailedLogin > 10
```

**Changes made and why:**

- **Dropped `IpAddress` from the grouping.** In this data, `IpAddress` was empty for the RDP `4625` events. Grouping by an empty field adds nothing and can fragment counts. Grouping by `Account` and `Computer` — the two populated, meaningful fields — gives a clean count of failures per account per host.
- **Threshold inside the query (`where FailedLogin > 10`).** The filter sits *after* `summarize`, because the aggregated `FailedLogin` field only exists once the summarize runs. Filtering an aggregate before it is created is a common KQL error and is avoided here.
- **`> 10` chosen deliberately** (see threshold reasoning below).

---

## Rule configuration

![Analytics rule summary: RDP brute-force detection with query, hourly schedule, >0 threshold, and Account/Host entity mapping](https://github.com/KevoT0/RDP-Brute-Force-Scheduled-Analytics-Rule/blob/main/7.png)

| Setting | Value | Reasoning |
|---|---|---|
| Name | RDP Brute-Force — Failed Logon Spike | Clear, describes the detection |
| Severity | Medium | An *attempt*, not a confirmed breach; escalate to High only on a successful logon |
| MITRE ATT&CK | Credential Access (T1110) | Brute force is a credential-access technique |
| Rule frequency | Every 1 hour | Runs hourly |
| Rule period | Last 1 hour | Each run scans the previous hour |
| Alert threshold | Results > 0 | The `> 10` filter lives in the query, so any returned row already qualifies |
| Event grouping | All events into a single alert | One alert per run |
| Create incidents | Enabled | Produces an investigable incident in the queue |
| Alert grouping | Enabled, match all entities | Groups related alerts (see trade-off below) |

**How the time window is actually formed:** the query itself has no time filter — the window comes from the schedule. Frequency (every 1 hour) + period (last 1 hour) + threshold (`> 10`) combine to mean:

> *"Every hour, look at the last hour of failed logons. If any account had more than 10 on a machine, raise an incident."*

**Threshold justification (`> 10` / 1 hour):** A threshold of 5 is too sensitive — a user mistyping a password 5–6 times on a Monday morning would trigger it, producing false positives. More than 10 failures within a single hour is far more clearly an attack or a seriously broken login than ordinary human error. In production this would be tuned based on observed false-positive rate: too noisy → raise it; missing real attacks → lower it. Starting at a defensible number and tuning against reality is the intended approach.

---

## Entity mapping

Entity mapping tells Sentinel that a result column represents a real, classifiable object rather than plain text — which is what makes the resulting incident investigable and pivotable.

| Entity | Identifier | Query column |
|---|---|---|
| Account | Name | `Account` |
| Host | HostName | `Computer` |

`Name` was chosen for the account because the data is formatted as bare account names (e.g. `\ADMINISTRATOR`) rather than full `DOMAIN\user` — the identifier was matched to the actual shape of the data rather than picked blindly.

---

## Alert grouping trade-off (analysis)

The rule uses **"match all entities"** grouping: two alerts merge into one incident only if *all* entities match (same Account **and** same Host). Because a brute-force spray hits many *different* accounts on the *same* host, this can produce several incidents for a single campaign against one machine.

- **Match all entities** (current): more incidents, each precise to an account.
- **Match any entity**: would group everything hitting one host into a single incident — arguably better for a spray, where the real story is *"this host is under attack"* rather than *"this account is."*

Neither is strictly correct; understanding the trade-off is the point. For a spray specifically, "match any" often reduces alert fatigue while still capturing the campaign.

---

## Validation

After creation, no incident appeared in the queue on the live 1-hour schedule. **This is the correct, expected result** — not a failure.

- The rule scans the **last 1 hour of real time.**
- The brute-force activity in the dataset is **historical** (the Training Lab data is static and does not regenerate), so it falls outside a live 1-hour window.
- The rule therefore correctly finds nothing to detect *right now*.

**Proving the logic is sound** despite the quiet live result — running the same logic against the data's actual time range returns results:

```kql
SecurityEvent
| where TimeGenerated > ago(14d)
| where EventID == 4625
| summarize FailedLogin = count() by Account, Computer
| where FailedLogin > 10
```

This returns the brute-force accounts, confirming the detection logic is correct. The only reason the scheduled rule stays quiet is the recency of the lab data — in production, against live telemetry, the same rule would fire on a real attack.

> **Interview framing:** the rule is correctly built and validated. It does not fire on a live 1-hour schedule only because the lab dataset is historical. Distinguishing *"correctly quiet against stale data"* from *"broken"* is essential — an analyst who assumes a quiet rule is broken looks junior; one who explains why it is quiet and how to validate it anyway demonstrates detection-engineering understanding.

**Production note:** if the lookback is widened to reach historical data for testing, it must be returned to 1 hour before shipping. Widen-to-test, narrow-to-ship — a rule scanning many days every hour is expensive and noisy in production.

---

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1110 – Brute Force | High-volume failed logons against accounts on internet-facing hosts |

---

## Lessons learned

- **Hunting and detection engineering are different skills.** A hunt is a one-time question; a detection is that question automated, scheduled, and thresholded.
- **The time window comes from the schedule, not the query.** Frequency + period + threshold together define what "a burst" means.
- **Match the entity identifier to the data's shape.** Bare names → `Name`; `DOMAIN\user` → `FullName`.
- **A quiet rule is not automatically a broken rule.** Against historical data, "no incident" can be the correct output; validate the logic separately.
- **Thresholds are judgement calls to be defended and tuned**, not fixed values.
- **Widen-to-test, narrow-to-ship.** Test windows and production windows serve different purposes.

---

## Skills demonstrated

Detection engineering · Converting hunts into scheduled analytics rules · KQL query tuning · Entity mapping · Alert threshold justification · Alert-grouping trade-off analysis · Rule validation against historical data · MITRE ATT&CK mapping
