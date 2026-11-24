# Playbook: CloudTrail logging stopped, deleted or modified

**Rule:** `aws_cloudtrail_logging_tampering` · **Severity:** critical ·
**ATT&CK:** T1685.002 Disable or Modify Cloud Log

Someone tried to blind the logs. Treat it as an attacker until shown otherwise, because
logging is often the first thing an attacker turns off.

## First 15 minutes

1. **Did it work?** Look at `errorCode` in the alert.
   - `AccessDenied`: the guardrail held. The question is now *who tried and why*.
   - No error: logging may be off. Run `aws cloudtrail get-trail-status --name <trail>`
     and check `IsLogging` straight away.
2. **Who?** `userIdentity.arn`, `userIdentity.type`, `sourceIPAddress`, `userAgent`.
   An Identity Center role name (`AWSReservedSSO_<permission set>_...`) tells you which
   permission set, and the session name after the last `/` is the user.
3. **What else did that identity do?** Pull everything from the same principal around the
   alert:

   ```
   from detlab-cloudtrail
   | where userIdentity.arn == "<arn from the alert>"
   | where @timestamp > now() - 24 hours
   | keep @timestamp, eventSource, eventName, awsRegion, errorCode, sourceIPAddress
   | sort @timestamp
   ```

   Look for the usual pattern: tampering first, then `CreateAccessKey`,
   `CreateUser`, `RunInstances` in another region, or S3 reads.

## Contain

- If logging is off: turn it back on (`aws cloudtrail start-logging`) before anything else.
- If the identity isn't a known admin doing planned work: remove the user's account
  assignment in Identity Center and revoke active sessions (deny statement with an
  `aws:TokenIssueTime` condition on the role, or disable the user at the IdP).
- If an IAM user or access key was used: deactivate the key.

## Eradicate and recover

- Restore the trail configuration from the Project 8 as-built doc and confirm the
  organisation trail covers all accounts and regions again.
- Work out the logging gap (from `StopLogging` to `StartLogging`) and write it in the incident
  record. Anything that happened in that window is unknown.

## Escalate when

- Logging was actually stopped, or the trail deleted (not just denied).
- The identity isn't a lab admin, or the source IP isn't one you recognise.
- Any of the other high or critical rules fired for the same identity in the last 24 hours.

## Close as benign when

- A planned trail change by the lab admin, with a matching change log entry. Note the
  change reference in the alert before closing.
