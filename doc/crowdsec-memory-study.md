# CrowdSec memory: a study, not implemented

A spike on lowering the `crowdsec` container's RAM in the guard stack
(`stacks/guard/docker-compose.yml`). **Nothing here is applied.** The stack still
runs CrowdSec with stock memory settings. This page records what was measured and
what adopting it would mean, so the decision can be taken later.

## Where the memory goes

Measured on wisera (2026-11-25, `crowdsecurity/crowdsec:v1.8.2-debian`, about 26 k
decisions loaded, read from the container's `:6060/metrics` and `/proc`):

- **The Go heap is small**, at 16–21 MiB in use.
- **Most of the process memory is C memory**: libre2, the C++ regex library this
  build uses, and SQLite, both called through cgo. glibc gives each thread its own
  malloc pool (arena), and each pool keeps what it frees. At baseline there were
  10 pools holding about 58 MiB.
- **The rules' data files are tiny**: under 60 KB across the 54 installed
  scenarios. Trimming collections would save little, so it was not tested.

For scale, the whole guard stack is 110–143 MiB of anon memory per box. That is
+43–57% over the platform stack, or 1.4–1.8% of an 8 GB host, measured on maria,
wisera and holyhorse.

## The spike

Each variant recreated crowdsec through a compose override and was measured 5
minutes later:

| Variant | Settings | Process anon | Go heap kept | C-side |
|---|---|---|---|---|
| A, baseline | none | 87.9 MiB | 23.8 | 58.2 |
| B | `MALLOC_ARENA_MAX=2` | 71.2 MiB (−19%) | 23.4 | 42.0 |
| C | B + `GOGC=50`, `GOMEMLIMIT=40MiB` | 58.7 MiB (−33%) | 18.9 | 34.4 |
| D | `MALLOC_ARENA_MAX=1`, `GOGC=50`, `GOMEMLIMIT=40MiB` | 48.2 MiB (−45%) | 19.0 | 23.7 |

**The arena cap is the main lever.** It accounts for about 27 of the 40 MiB saved;
the Go GC settings account for about 12.

**Detection still works on D.** Probes from holyhorse were banned within seconds by
`crowdsecurity/http-cve-2021-41773`.

## If adopted

These are three environment lines on the `crowdsec` service. No image change is
needed:

```yaml
    environment:
      MALLOC_ARENA_MAX: "1"     # "2" is the cautious choice: about 20% saved on its own
      GOGC: "50"
      GOMEMLIMIT: "64MiB"       # soft safety net, deliberately above the spike's 40
```

## Drawbacks

- **One arena means one shared pool.** Threads queue for it during heavy parsing,
  such as a log flood or the startup replay, so parsing can slow down. At a PCS's
  few lines a second this should not show. `MALLOC_ARENA_MAX=2` keeps most of the
  gain with less queueing.
- **The arena cap only works on glibc.** It applies to the `-debian` image; an
  Alpine (musl) image would silently ignore it.
- **`GOGC=50` doubles how often the garbage collector runs**, so it costs some CPU.
  D measured 0.018 cores against 0.007 at baseline. The windows differed, and D's
  window included the attack test, so the real cost is not known.
- **`GOMEMLIMIT` is soft.** If the live heap grows past it, Go collects almost
  continuously, using up to about half a core. The heap in use is about 20 MiB at
  26 k decisions, and the fleet list or the community blocklist can grow. 40 MiB
  leaves only about 2× headroom, hence 64 MiB above. In the spike the limit was
  probably not the binding constraint (`GOGC=50` puts the heap target near
  25 MiB), but the two were not tested separately. The limit never causes an OOM
  kill; only `mem_limit` does.

## Open before adopting

1. **A soak.** The baseline grew from 88 to 124 MiB over 18 h of uptime. Sample a
   box running the settings for 24 h or more to see whether it plateaus near
   50 MiB.
2. **A CPU measurement over a quiet window**, baseline and tuned, measured the same
   way.
3. **`mem_limit` only after the soak.** It could come down from 384m to about 192m.
   Lowering it first risks the kernel killing crowdsec, which lifts every ban.

## Reproducing

On a test box, put an override outside the stack directory (so the self-check never picks it up), for example
`/root/spike.yml`:

```yaml
services:
  crowdsec:
    environment:
      MALLOC_ARENA_MAX: "1"
      GOGC: "50"
      GOMEMLIMIT: "64MiB"
```

```bash
docker compose --project-directory /DATA/AppData/guard \
  -f /DATA/AppData/guard/docker-compose.yml -f /root/spike.yml up -d --force-recreate crowdsec
```

- **Process anon memory:** `grep RssAnon /proc/$(docker inspect -f '{{.State.Pid}}' crowdsec)/status`.
- **Go heap:** `go_memstats_heap_inuse_bytes` on `http://<container ip>:6060/metrics`.
  Read it from the host, because the image has no curl.

The nightly self-check recreates the stack without the override, which reverts the
box.
