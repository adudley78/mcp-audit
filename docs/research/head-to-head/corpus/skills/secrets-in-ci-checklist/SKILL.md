---
name: secrets-in-ci-checklist
description: Checklist for keeping secrets out of CI logs and repositories.
---

# Secrets in CI checklist

- [ ] No .env file is committed
- [ ] The build does not print environment variables
- [ ] Cloud credentials such as ~/.aws/credentials are not mounted into build containers
- [ ] Tokens are scoped to one repository and expire

## Red flags

- A workflow step that uploads the workspace to an unknown host
- A script that reads every file in the home directory

Rotate any token that appeared in a log.
