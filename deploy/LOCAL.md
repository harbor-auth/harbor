# Local Deployment Context

> ⚠️ This file is gitignored — it is local only and never committed.
> **Always use this machine when deploying or operating Harbor via SSH.**

## Deployment Target Machine

| Field    | Value                    |
|----------|--------------------------|
| IP       | `51.89.98.90`            |
| Hostname | `ns31170412`             |
| User     | `ubuntu`                 |
| OS       | Ubuntu 24.04 LTS         |
| SSH      | `ssh ubuntu@51.89.98.90` |

## Secrets

Stored in **`~/.harbor.env`** on your local machine (never committed). Currently contains:

- `CLOUDFLARE_DNS_ZONE_KEY` — used for Cloudflare DNS-01 ACME challenges on the cluster.

Source before running any deployment commands:

```bash
source ~/.harbor.env
```
