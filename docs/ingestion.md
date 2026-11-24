# Getting the logs in

Raw logs go in `data/` (gitignored) and get loaded with `detlab ingest`. Re-running ingest on
the same files is safe: each document uses the event's own ID, so nothing is duplicated.

## AWS CloudTrail (organisation trail bucket)

Use an IAM Identity Center permission set, not an access key. The roadmap's rule is no
long-lived keys, and rule `aws_iam_access_key_created` would flag you anyway.

1. In the management account, create a permission set (for example `DetectionLabLogReader`)
   assigned only to you, on the log archive account, with read access to the trail bucket:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": ["s3:ListBucket"],
         "Resource": "arn:aws:s3:::YOUR-ORG-TRAIL-BUCKET"
       },
       {
         "Effect": "Allow",
         "Action": ["s3:GetObject"],
         "Resource": "arn:aws:s3:::YOUR-ORG-TRAIL-BUCKET/AWSLogs/*"
       }
     ]
   }
   ```

   If the bucket uses SSE-KMS, also allow `kms:Decrypt` on that key.

2. Sign in and sync only the days you need (small download, a few cents at most):

   ```bash
   aws configure sso --profile p9-logreader      # first time only
   aws sso login --profile p9-logreader
   aws s3 sync "s3://YOUR-ORG-TRAIL-BUCKET/AWSLogs/YOUR-ORG-ID/" data/cloudtrail/ \
     --exclude "*" --include "*/CloudTrail/*/2026/12/*" --profile p9-logreader
   ```

3. Load them:

   ```bash
   detlab ingest data/cloudtrail
   ```

CloudTrail usually delivers events to S3 within 5 to 15 minutes, so wait before syncing after
a test. Digest files are skipped automatically.

## Microsoft Entra ID (Free tier)

The Graph API for sign-in logs needs Entra ID P1 or P2, so on the Free tier use the portal
export. Free keeps sign-in and audit data for **7 days**, so export soon after each test.

1. Entra admin center → **Monitoring & health → Sign-in logs** → set the date range →
   **Download → JSON**. Save it under `data/entra/`.
2. Same for **Audit logs**.
3. Load them:

   ```bash
   detlab ingest data/entra
   ```

`detlab ingest` recognises each record by its fields (`createdDateTime` +
`userPrincipalName` for sign-ins, `activityDisplayName` + `activityDateTime` for audit
events). The rules and fixtures assume the portal export uses the same field names as the
Microsoft Graph `signIn` and `directoryAudit` resources. **Check this on your first
export:** if records show up as "skipped", or a rule doesn't fire on a test you know
happened, compare a real record with the fixture for that rule and fix whichever is wrong.
Then update the fixture so the test matches reality.

## Check it landed

In Kibana Discover, using the `detlab-*` data view:

- `detlab.source : "cloudtrail"` should show your recent API calls
- `detlab.source : "entra_signin"` should show your own sign-ins

Or with ES|QL:

```
from detlab-* | stats events = count() by detlab.source
```
