# Evidence

Redacted screenshots of each alert from the lab tests, named `<rule name>.png`, plus
anything else that backs a claim in the README.

Keep the unredacted originals in `evidence/raw/` (gitignored) or outside the repo.

## Redact before committing

Check every screenshot for these and blur or box them out:

- AWS account IDs and organisation ID (`o-...`)
- Entra tenant name, tenant ID and real user principal names
- Public IP addresses (your home or uni IP)
- Email addresses
- Access key IDs, session tokens, ARNs that include an account ID
- Browser tabs or bookmarks that show anything personal

Then zoom in on the saved file and check again. Redaction that only covers part of a value,
or a value that shows up twice, is easy to miss.
