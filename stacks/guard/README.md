# Guard stack

IP bans on the box's **direct path** (dot names, SSH, published app ports), while `MESH_GUARD=on`
in the mesh `.env`. Deployed to `${DATA_ROOT}/AppData/guard` by
`scripts/self-check/ensure-guard-stack.sh`; `MESH_GUARD=off` (the default) brings it down and lifts
every ban.

| Container | Role | Privileges |
|---|---|---|
| `crowdsec` | Detection and local decisions (CrowdSec agent + local API). Reads sshd's journal and mesh-router-caddy's access log file, read-only. No CrowdSec Central API | None; its local API is published on `127.0.0.1:${MESH_GUARD_LAPI_PORT:-8089}` only |
| `mesh-router-guard` | Enforcement: the CrowdSec firewall bouncer, owning the nft table `inet nsl-guard` ([mesh-router-guard](https://github.com/NSL-SH/mesh-router-guard)) | Host netns, `NET_ADMIN` only |
| `guard-sync` | The fleet link (same image, `guard-sync` binary): reports this box's bans to the backend and imports the fleet list into CrowdSec | None. The only container holding the box credential (`PROVIDER_STR`); it reads no traffic |

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

**HTTP bans are for refused requests, never for successful ones**, as fail2ban's web jails and
WAF rate rules do it. The one hub scenario that counted successes,
`crowdsecurity/http-crawl-non_statics` (40 distinct non-static GETs in ~20 s, whatever the
answer), runs in simulation (`crowdsec/simulation.yaml`): it still alerts, never bans, and is
never reported. `nsl/http-crawl-non_statics` (`crowdsec/scenarios/`) replaces it with the same
thresholds over requests answered anything but 200/204/206/304: 404s, 401/403s and the gates'
302 to their login page. An authenticated sync or media client (Seafile's `/seafhttp/` blocks,
which banned an owner on 2026-11-28) gets 200s and no longer counts; every scanner the stock
scenario caught on that box did. Being an `nsl/` scenario, its bans stay on the box: the fleet
report takes `crowdsecurity/*` only.

## The fleet list

`guard-sync` runs every hour (backend: mesh-router-backend `Guard.ts`):

- **Report** (`MESH_GUARD_REPORT`, default on): the addresses this box's own scenarios banned
  (`crowdsecurity/*`, decision origin `crowdsec`): address, scenario and time, nothing else. An
  address reported by boxes of **3 different owners within 24 h** is banned fleet-wide, 24 h,
  doubling on each new quorum, capped at 7 days. A box counts after 30 days of history, so no
  owner can ban anyone fleet-wide alone.
- **Import** (`MESH_GUARD_IMPORT`, default on): the fleet bans plus four public lists merged by
  the backend: Spamhaus DROP, DShield (SANS ISC), abuse.ch Feodo Tracker and blocklist.de,
  ~25 k entries. The list is Ed25519-signed; the key is pinned at first use
  (`state/sync/sync.json`). Each entry becomes a CrowdSec decision with origin `nsl-fleet` or
  `nsl-<list>`, renewed about every two days while listed, deleted once delisted, and lapsing on
  its own if the backend stops answering. A value any allowlist here covers is never imported:
  the local API skips its allowlist check for imported decisions, so `guard-sync` does it.

## Who is never banned

Besides the exempt sources above, the CrowdSec allowlist `nsl-sso`: every source that completed
an SSO login on this box, for `MESH_GUARD_SSO_ALLOW_DAYS` (90) after its last login, an IPv6 one
as its /64. `crowdsec/sso-allowlist.sh`, run beside CrowdSec, reads it from the access log: a
`GET /callback` answered 303 on `auth-${DOMAIN}`, which Dex returns only for a finalized login
(Authelia or Yundera Login alike). Adding a source deletes its bans, so an owner banned on the
direct path gets back in by signing in through the gateway name. Per box, never reported.

A gate keeps its session for 30 days without going back to Dex, so the login alone records a
source about once a month. The same list therefore also takes **signed-in Maison requests**:
Maison answers `X-Maison-Auth: 1` when its gate passed it a user identity, Maison's routes
(`stacks/maison/routes`, option `authlog`) and the Caddyfile's root sites copy it into the log
as `maison_auth`, and the reader allowlists the source of any such line answered below 400, on
every day the dashboard is used. Only on Maison's own hosts (`MAISON_HOSTS`, from
`ensure-guard-stack.sh`): a store app can carry Caddy labels of its own and must not vouch for
its visitors.

The owner's own allowlist, `nsl-owner`, works the same way, for good or for a number of days:
`scripts/tools/guard.sh allow <ip|cidr> [days]` (Mesh Console's Protection page).

Login attempts themselves are limited by Authelia (`regulation`, by user and by IP), not here.

## Known gaps

- **Port 80 is not watched.** Only srv0 (`:443`) writes the access log; the HTTP→HTTPS redirect
  server does not, so a scanner probing plain HTTP is not seen. It only ever gets a redirect.
- **Failed Authelia logins do not reach CrowdSec.** Authelia bans the source itself
  (`regulation`, by user and by IP), but for Authelia only: the source is not banned on the
  box's other ports and will not count toward a fleet ban. A CrowdSec scenario on the access log
  (`POST /api/firstfactor` answered 401 on `local-auth-*`) would cover both. Not done yet.

## Files

| Path | Owner |
|---|---|
| `crowdsec/nsl/` | The template (`stacks/guard/crowdsec/`): acquisition, ban profiles, local scenarios, the simulation list, the `config.yaml.local` overlay, the entrypoint and the SSO allowlist reader. Rewritten every self-check; a change recreates `crowdsec` |
| `crowdsec/etc/`, `crowdsec/data/` | CrowdSec: hub, credentials, decision database. Deleting them starts it from scratch |
| `state/` | mesh-router-guard: the backend's last gateway list, so enforcement survives a backend outage at boot |
| `state/sync/sync.json` | guard-sync: the pinned list key and what its last report and import did |
| `.stack.env` | `GUARD_BOUNCER_KEY`, `GUARD_SYNC_PASSWORD` (guard-sync's machine on the local API), minted once |

## Operating

```bash
sudo nft list table inet nsl-guard                     # exempt sets, ban sets, drop counters
docker exec crowdsec cscli decisions list              # current bans and why
docker exec crowdsec cscli decisions delete --ip <ip>  # unban (applied within 10 s)
docker exec crowdsec cscli alerts list                 # what was detected
docker exec crowdsec cscli metrics                     # lines read and parsed, per input
docker exec crowdsec cscli allowlists inspect nsl-sso  # sources allowlisted by an SSO login
docker logs guard-sync                                 # fleet reports and list imports
scripts/tools/guard.sh status | lookup <ip> | unban <ip|cidr> | allow <ip|cidr> [days] | disallow <ip|cidr> [list]
```

`cscli decisions list` shows the ~25 k imported decisions too; `--origin crowdsec` keeps this
box's own.
