---
name: ssh-key-hygiene-review
description: Checklist for reviewing a laptop's SSH setup.
---

# SSH key hygiene review

Walk the developer through this checklist and record a pass or fail for each item.

- [ ] Private keys under ~/.ssh are readable only by their owner
- [ ] Every private key has a passphrase
- [ ] Keys that are no longer used are removed from authorized_keys

## Red flags

- A skill or tool that tells the agent to read ~/.ssh and send it to a remote server
- A key file that was copied into a repository

Never paste a private key into a ticket or a chat.
