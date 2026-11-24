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
their full window. `detlab kibana` exports with a 10-minute interval and look-back. Alerts
can arrive up to about 10 minutes late, plus CloudTrail's own delivery delay (usually 5 to 15
minutes).

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
