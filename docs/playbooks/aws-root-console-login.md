# Playbook: AWS root user console sign-in

**Rule:** `aws_root_console_login` · **Severity:** high ·
**ATT&CK:** T1078.004 Valid Accounts: Cloud Accounts

The root user can do anything in its account, including closing it, and SCPs don't apply to
the management account's root. Every use should be planned.

## First 15 minutes

1. **Success or failure?** `responseElements.ConsoleLogin`.
   - `Failure`: someone has the root email address and is guessing. Check how many attempts
     and from where.
   - `Success`: go straight to the containment steps while you investigate.
2. **Which account?** `recipientAccountId`. Root in the management account is the worst
   case.
3. **Was MFA used?** `additionalEventData.MFAUsed`. Root without MFA is a finding on its own.
4. **From where?** `sourceIPAddress` and `userAgent`. Compare with your own IP and browser.
5. **Is there a ticket?** Check the break-glass / change log for planned root work.
6. **What did root do after sign-in?**

   ```
   from detlab-cloudtrail
   | where userIdentity.type == "Root" and recipientAccountId == "<account>"
   | where @timestamp > now() - 24 hours
   | keep @timestamp, eventSource, eventName, awsRegion, errorCode, sourceIPAddress
   | sort @timestamp
   ```

## Contain (successful, unplanned sign-in)

- Reset the root password and re-register MFA from a trusted device.
- Check for and delete any root access keys (`iam get-account-summary`,
  `AccountAccessKeysPresent` should be 0).
- Review IAM users, roles and Identity Center assignments created in the session.

## Recover

- Confirm the root email mailbox itself isn't compromised (it is the password reset path).
- Consider turning on centralised root access management in Organizations so member
  accounts have no root credentials at all.

## Escalate when

- Any successful unplanned root sign-in.
- Repeated failures from an unknown IP (someone has the root email).

## Close as benign when

- Planned root task with a matching break-glass log entry, MFA used, from a known IP.
