# Lab testing guide

How to trigger each rule safely in the real lab and prove the alert fires.

## Rules of engagement

- Only my own lab: the Project 8 AWS organisation (Dev account unless stated) and my own
  Entra tenant. Never the Deakin tenant or anything I don't own.
- Use throwaway test identities (`detlab-test-*`) and delete or disable them the same day.
- Nothing here needs a paid service. AWS budget alert stays at US$5.
- Before each test, write down the start time (UTC). After it, record the result in
  `validation/lab-tests.yml` and run `detlab coverage`.

## Test flow for every rule

1. Do the trigger below and note the UTC time.
2. Wait for delivery: CloudTrail takes 5 to 15 minutes to reach S3; Entra shows sign-ins in
   a few minutes.
3. Export or sync the logs and run `detlab ingest` (see `ingestion.md`).
4. Check **Security → Alerts** in Kibana. The rules run every 10 minutes. The AWS and
   single-event Entra rules look back 60 minutes, so ingest within about 45 minutes of the
   trigger and they alert on their own. The two correlation rules only look back 10 minutes
   (see `design-notes.md`), and so does anything ingested later: open the rule → **⋯ →
   Manual run** and give it a time range around the trigger.
5. Screenshot the alert, redact it (see `evidence/README.md`), and save it as
   `evidence/<rule name>.png`.
6. Clean up as listed.

## AWS

### aws_root_console_login
- **Trigger:** on the AWS sign-in page choose "Root user", enter the Dev account's root
  email and a **wrong password**. The rule alerts on failed root attempts as well, so no
  real root sign-in is needed.
- **Expect:** `ConsoleLogin` with `userIdentity.type: Root` and `ConsoleLogin: Failure`.
- **If no event appears:** if centralised root access is turned on in Organizations, member
  accounts may have no root sign-in at all. Mark it "not testable" with that reason
  instead of weakening controls to get a screenshot.
- **Clean-up:** none.

### aws_cloudtrail_logging_tampering
- **Trigger:** as your Dev admin permission set, try to stop the organisation trail. It is
  owned by the management account, so the call is denied:
  `aws cloudtrail stop-logging --name <org-trail-ARN> --profile dev-admin`
- **Expect:** `StopLogging` with `errorCode: AccessDenied`. Logging is never interrupted.
- **Clean-up:** none. Confirm afterwards that `aws cloudtrail get-trail-status` still shows
  `IsLogging: true`.

### aws_console_login_without_mfa
- **Trigger:** in Dev, create IAM user `detlab-test-user` with a console password and no
  MFA, sign in once in a private window, sign out.
- **Expect:** `ConsoleLogin` with `userIdentity.type: IAMUser` and `MFAUsed: No`.
- **Clean-up:** delete the user straight after (login profile first, then the user).
  This is an IAM user in a "zero IAM users" design, so record it in the change log.

### aws_iam_access_key_created
- **Trigger:** on the same `detlab-test-user`, create an access key. **Don't download or
  use it.** Delete it straight away.
- **Expect:** `CreateAccessKey` (and a `DeleteAccessKey` that must not alert).
- **Clean-up:** key deleted, then user deleted.

### aws_guardrail_policy_change
- **Trigger:** in the management account, create a test SCP `detlab-test-scp` that is **not
  attached** to anything, edit its description once, then delete it.
- **Expect:** `CreatePolicy`, `UpdatePolicy` and `DeletePolicy` from
  `organizations.amazonaws.com`: three alerts.
- **Clean-up:** policy deleted. No OU or account was affected because it was never attached.

### aws_activity_outside_approved_region
- **Trigger:** try to create something outside Sydney; the Sydney-only policy denies it:
  `aws sns create-topic --name detlab-test --region us-east-1 --profile dev-admin`
- **Expect:** `CreateTopic` in `us-east-1` with an AccessDenied error. If it **succeeds**,
  that is a finding about the region guardrail: delete the topic and log it.
- **Clean-up:** none if denied.

## Entra ID

### entra_break_glass_signin
- **Trigger:** do the scheduled break-glass sign-in test from Project 8 (sign in, check
  access, sign out). Record it in the break-glass log as usual.
- **Expect:** a sign-in for the break-glass UPN. Make sure the rule's prefix matches your
  naming before testing.
- **Clean-up:** none.

### entra_privileged_role_assigned
- **Trigger:** create test user `detlab-test-admin`, **block its sign-in**, assign it
  Privileged Role Administrator, then remove the assignment a few minutes later. A blocked
  account can't be used even while it holds the role.
- **Expect:** an "Add member to role" audit event with that role name.
- **Clean-up:** remove the role, delete the user. Note this also tests the alert path
  behind Project 8's RB-004 (keeping Global Admins to the approved few).

### entra_mass_user_disable
- **Trigger:** create five test users `detlab-test-01` to `05`, then disable all five
  within a few minutes, starting just after a :00 or :10 minute mark so the burst sits in
  one 10-minute bucket (see `design-notes.md`).
- **Expect:** five "Disable account" events from your admin account, one alert.
- **Clean-up:** delete the five users.

### entra_repeated_failed_signins
- **Trigger:** in a private window, enter a wrong password for `detlab-test-01` (re-create
  it if needed) 10 to 12 times in a few minutes. Never use a real admin account: Smart
  Lockout will lock it.
- **Expect:** error 50126, then 50053 once Smart Lockout kicks in. One alert.
- **Clean-up:** delete the test user.
