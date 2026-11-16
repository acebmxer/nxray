---
name: Bug report
about: Something in NXray does not work as documented
title: '[Bug] '
labels: bug
assignees: ''
---

## What happened

<!-- A clear description of what went wrong. Paste error messages exactly. -->

## What you expected

## Steps to reproduce

1. Open NXray and go to `...`
2. Click / enter `...`
3. See error

## Logs

<!-- docker compose logs nxray, with addresses, usernames and anything else
     sensitive removed. -->

```
(paste output here)
```

## Environment

| Field | Value |
|-------|-------|
| NXray version | <!-- page footer, e.g. "NXray v0.3.0", or `curl -s localhost:8080/healthz` --> |
| Switch model & NX-OS version | <!-- from `show version` --> |
| Docker | <!-- output of `docker --version` --> |
| Host OS | <!-- e.g. Fedora 45, Ubuntu 26.04 --> |
| Page affected | <!-- e.g. Dashboard, Ports, VLANs, Settings --> |

## Does the same happen on the switch itself?

<!-- If you can, run the matching command in the switch CLI. This tells us
     whether the problem is in NXray or on the switch. -->

- [ ] Same result on the switch CLI
- [ ] The switch CLI is right, only NXray is wrong
- [ ] Not tried

## Additional context

<!-- Screenshots or anything else that might help. -->
