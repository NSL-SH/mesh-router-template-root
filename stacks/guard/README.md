# Guard stack

IP bans on the box's **direct path** (dot names, SSH, published app ports), while `MESH_GUARD=on`
in the mesh `.env`. Deployed to `${DATA_ROOT}/AppData/guard` by
`scripts/self-check/ensure-guard-stack.sh`; `MESH_GUARD=off` (the default) brings it down and lifts
every ban.

| Container | Role | Privileges |
|---|---|---|
| `crowdsec` | Detection and local decisions (CrowdSec agent + local API). Reads sshd's journal and mesh-router-caddy's access log file, read-only. No CrowdSec Central API | None; its local API is published on `127.0.0.1:${MESH_GUARD_LAPI_PORT:-8089}` only |
| `mesh-router-guard` | Enforcement: the CrowdSec firewall bouncer, owning the nft table `inet nsl-guard` ([mesh-router-guard](https://github.com/NSL-SH/mesh-router-guard)) | Host netns, `NET_ADMIN` only |

Relayed traffic (gateway, tunnel) is never dropped: the gateways, the tunnel providers and the
backend are exempt, read from `<backend>/router/api/version`; so are the box itself, the private
ranges and `MESH_GUARD_EXEMPT`. Design: the PCS edge-protection study
(`yundera-root/doc/study/pcs-edge-protection-study.md`).

## What it detects

| Input | Collections |
|---|---|
| sshd, from the host journal (`journalctl --root=/host`, unit `ssh.service`): Ubuntu and Debian 13 alike | `crowdsecurity/sshd` (brute force, user enumeration) |
| `mesh/data/caddy/log/access.log` (`MESH_ACCESS_LOG`, which follows `MESH_GUARD`): request line, status, client IP, host; no headers | `crowdsecurity/caddy`, `base-http-scenarios`, `http-cve` |

A ban lasts 4 h, doubling on each repeat within CrowdSec's 7-day memory, capped at 7 days
(`crowdsec/profiles.yaml`).

## Files

| Path | Owner |
|---|---|
| `crowdsec/nsl/` | The template (`stacks/guard/crowdsec/`): acquisition, ban profiles, the `config.yaml.local` overlay. Rewritten every self-check; a change recreates `crowdsec` |
| `crowdsec/etc/`, `crowdsec/data/` | CrowdSec: hub, credentials, decision database. Deleting them starts it from scratch |
| `state/` | mesh-router-guard: the backend's last gateway list, so enforcement survives a backend outage at boot |
| `.stack.env` | `GUARD_BOUNCER_KEY`, minted once |

## Operating

```bash
sudo nft list table inet nsl-guard                     # exempt sets, ban sets, drop counters
docker exec crowdsec cscli decisions list              # current bans and why
docker exec crowdsec cscli decisions delete --ip <ip>  # unban (applied within 10 s)
docker exec crowdsec cscli alerts list                 # what was detected
docker exec crowdsec cscli metrics                     # lines read and parsed, per input
```
