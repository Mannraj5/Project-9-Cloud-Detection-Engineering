# Design notes

Decisions and gotchas found while building the lab. Most of these were found by testing,
not by reading, and each one is covered by a test or a lint check so it can't quietly come
back.

## Why ES|QL and not Lucene/KQL

pySigma's Elasticsearch backend can output Lucene, EQL or ES|QL. Lucene can't express Sigma
correlation rules ("10 failures in 10 minutes"), and two of the rules need that. ES|QL
handles both kinds, so every rule uses one query language, and Elastic Security can run all
of them as ES|QL rules.

## Why raw field names instead of ECS

Elastic's own AWS integration renames CloudTrail fields to ECS (`eventName` becomes
`event.action` and so on). I kept the original field names because:

- the Sigma rules stay the same as the logs AWS and Microsoft document, so anyone can read
  them against the official docs
- SigmaHQ's public CloudTrail rules use the same raw names, so their rules can be dropped in
- the ingest path stays simple (`aws s3 sync` plus `detlab ingest`) with no SQS queue or
  agent policy to set up

The cost is that this lab doesn't use Elastic's prebuilt dashboards.

## ES|QL behaves differently from the Sigma spec

Checked against Elasticsearch 8.19.7. The offline evaluator (`src/detlab/sigma_eval.py`)
copies this behaviour, and CI runs the same fixtures against a real Elasticsearch to prove
the two agree.

| Behaviour | What it breaks | What I did |
|---|---|---|
| A comparison on a **multi-valued field** returns null, so the row never matches. Both `==` and `like` fail on arrays. | Entra audit `targetResources[].modifiedProperties[].newValue` is an array, so a rule on the role name would never fire, with no error. | Ingest flattens those properties into `detlab.modified.<Name>` (single values, quotes removed). |
| **String matching is case-sensitive.** Sigma says it should be case-insensitive. | `BreakGlass01@` would not match a `breakglass` prefix. | Ingest adds `detlab.user_principal_name_lc`. Rules on AWS fields keep exact case because AWS writes them consistently. |
| **Three-valued logic.** A comparison on a missing field is null, and `not null` is still null. | A `not filter` on an absent field removes the event instead of keeping it. | Accepted and tested. See the "known gap" case in `aws_activity_outside_approved_region` (an event without `readOnly`). |
| A field that is not in the index mapping gives an **"Unknown column" error** and the whole rule fails. | A rule on a field that hasn't appeared in the index yet stops running. | Every field a rule uses is mapped in `elastic/index-template.json`, and `detlab lint` fails if one is missing. |
| Correlation rules count in **fixed `date_trunc` buckets**, not a sliding window. | A burst that straddles a bucket boundary is split and can be missed. | Accepted and tested (the "known gap" case in `entra_mass_user_disable`). A sliding window would need a different rule type. |

## Schedule and look-back

pySigma's default Elastic rule export runs every 5 minutes and looks back 5 minutes. The
correlation rules count over 10 minutes, so with a 5-minute look-back they could never see
their full window. `detlab kibana` runs every rule every 10 minutes.

**Late data.** The first lab test showed that a look-back equal to the interval is too
short here. CloudTrail took about 2 minutes to reach S3, the logs were pulled by hand and
ingested about 15 minutes after the event, and the rule had already searched that time
range. So the non-correlation rules now look back **60 minutes** (`--lookback`). Kibana
uses each event's `_id` to avoid duplicate alerts in the overlap, and the queries keep
`_id` (`metadata _id, _index, _version`, nothing drops it).

**Correlation rules keep look-back = interval.** Their `STATS ... BY` results have no `_id`.
Elastic's docs don't say how those are deduplicated, so it was tested on the lab cluster
(Elasticsearch/Kibana 9.5.7, 2026-11-26): a copy of the failed sign-in rule on its own
index, every 1 minute with a 30-minute look-back, over one burst of 12 failures. It raised
the same alert on 3 consecutive runs. A longer look-back would repeat correlation alerts,
so they stay at 10 minutes and late Entra exports are checked with a **manual run** over
the export's time range (rule → ⋯ → Manual run). Alert suppression could also fix this,
but it depends on the subscription level, and the lab drops to the Basic licence after
the trial.

## CloudTrail mapping conflicts

`requestParameters`, `responseElements`, `additionalEventData` and `serviceEventDetails`
have a different shape for every API call. If Elasticsearch maps them dynamically, the first
event decides the type and later events get rejected. The template sets those objects to
`dynamic: false` (stored but not indexed) and maps only the two sub-fields the rules use.
`date_detection` is off for the same reason.

## MITRE ATT&CK version

The roadmap was written against older ATT&CK names. ATT&CK v20.1 (the data pySigma 1.5.1
downloads) split Defense Evasion into **Stealth** (TA0005) and **Defense Impairment**
(TA0112), and moved "Disable or Modify Cloud Logs" from T1562.008 to **T1685.002**. The rule
tags use the v20.1 names, and `sigma check` validates them in CI.

## Fixtures use placeholders only

All sample events use account IDs `111111111111` and `222222222222`, documentation IP ranges
(`203.0.113.0/24`, `198.51.100.0/24`) and the reserved `lab.example` domain. `detlab lint`
fails if anything that looks like a real account ID, access key or email domain appears in
the fixtures, validation or evidence files.

## Tuning log

Changes made because real logs disagreed with the fixtures. Each one adds fixture cases so
the same mistake can't come back.

| Date | Rule | What real data showed | Change |
|---|---|---|---|
| 2026-11-26 | `aws_cloudtrail_logging_tampering` | `detlab check-export` on the Dev account's CloudTrail (47 records) found one match: `PutEventSelectors` on the organisation trail, made by `AWSServiceRoleForCloudTrail` with `invokedBy: cloudtrail.amazonaws.com`. That is CloudTrail copying the org trail's settings into the member account when the trail was created. A Critical false positive. | Exclude events only when **both** `userIdentity.invokedBy` is `cloudtrail.amazonaws.com` and the session issuer is `AWSServiceRoleForCloudTrail`. Only AWS can use that service-linked role. `is null` guards keep events without those fields alerting, because in ES\|QL a `not` on a missing field would drop them (a cross-account `StopLogging` has no session context). Four fixture cases cover the real event, a manual change, a near-miss role and the null case. |
| 2026-11-27 | `aws_root_console_login` | With centralised root access on, a failed root sign-in to a member account is not logged at all. The "Forgot password" attempt was: `PasswordRecoveryRequested` with `userIdentity.type: Root`. The rule only looked for `ConsoleLogin`, so it saw nothing. | Added `PasswordRecoveryRequested` to the rule (title now "…Sign-in or Password Recovery"). Two fixture cases: the real event, and a non-root one that must not match. |
| 2026-11-27 | `aws_activity_outside_approved_region` | The management account's logs had two root `ConsoleLogin` events in us-east-2 and us-west-2: AWS logs a console sign-in in the region of the sign-in endpoint that handled it. The rule only excused sign-in in us-east-1, so each one was a false positive. | Excluded `signin.amazonaws.com` in any region (sign-ins are covered by the root and no-MFA rules). Fixture case from the real event. |
