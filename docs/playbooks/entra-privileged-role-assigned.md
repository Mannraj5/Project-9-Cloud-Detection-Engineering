# Playbook: Entra ID tier-0 role assigned

**Rule:** `entra_privileged_role_assigned` · **Severity:** high ·
**ATT&CK:** T1098.003 Account Manipulation: Additional Cloud Roles

Global Administrator, Privileged Role Administrator and Privileged Authentication
Administrator can each take over the tenant. Giving one of them to a new account is a common
persistence step after an admin account is compromised.

## First 15 minutes

1. **Who gave it and to whom?** `initiatedBy.user.userPrincipalName` (actor) and
   `targetResources[0].userPrincipalName` (new role holder), plus
   `detlab.modified.Role_DisplayName`.
2. **Is it on the approved list?** The Project 8 design allows two break-glass accounts and
   one named admin as permanent Global Administrators. Anyone else needs a change record.
3. **Is the actor's own session trustworthy?** Check the actor's recent sign-ins:

   ```
   from detlab-entra-signin
   | where detlab.user_principal_name_lc == "<actor upn, lower case>"
   | where @timestamp > now() - 48 hours
   | keep @timestamp, ipAddress, appDisplayName, status.errorCode, location.countryOrRegion
   | sort @timestamp
   ```

   New IPs, new countries or a burst of failures before the success point to a
   compromised admin.
4. **What did the new role holder do?**

   ```
   from detlab-entra-audit
   | where initiatedBy.user.userPrincipalName == "<new role holder upn>"
   | where @timestamp > now() - 48 hours
   | keep @timestamp, activityDisplayName, result
   | sort @timestamp
   ```

## Contain

- Remove the role assignment.
- Revoke the new role holder's sessions (Entra admin center → user → **Revoke sessions**)
  and block sign-in until reviewed.
- If the actor looks compromised: revoke the actor's sessions too, reset the password and
  re-register MFA.

## Eradicate and recover

- Look for other persistence created in the same window: new app registrations or secrets,
  new users, Conditional Access policy changes, federation or domain changes.
- Record the before/after Global Administrator list in the incident record.

## Escalate when

- No change record, or the actor's sign-ins look abnormal.
- The role went to a newly created or guest account.

## Close as benign when

- Matches an approved change, and the new holder is on the approved admin list.
