# botwall

**Who delivers this site, who guards it, and what a plain request actually gets.**

One capped GET per host — the first 4 KB, redirects followed. It reads the response
headers and the start of the body, then reports three things separately, because
they are three different questions.

```
$ npx github:Bpx13303/botwall example-bank.com example-data.eu

HOST               CODE DELIVERED BY GUARDED BY          PLAIN REQUEST
------------------ ---- ------------ ------------------- -------------
example-bank.com   200  Akamai       Akamai Bot Manager  wall: challenge  (body looks like a gate, not content)
example-data.eu    206  CloudFront   —                   served  (nothing blocked at the door)
```

It does not bypass anything. It tells you what you are up against before you write
a scraper — or before you quote a job.

## Why the three columns

**Delivered by** is the CDN: Akamai, Cloudflare, CloudFront, Fastly. Their job is
speed, not defence. Nearly every large site has one, and its presence tells you
nothing about whether you will be blocked.

**Guarded by** is bot management: Akamai Bot Manager, DataDome, Cloudflare Bot
Management, HUMAN, Imperva, Kasada, F5, Queue-it. This is the thing that stops you.

They are usually sold by the same companies, which is why most tools conflate them
and tell you a public open-data portal is "protected by AWS" when nothing is
guarding it at all.

**Plain request** is what actually came back, and it is deliberately narrow: see below.

## Install

Node 18+ and `curl`. No dependencies, nothing to install:

```bash
npx github:Bpx13303/botwall example.com
```

## Usage

```bash
botwall example.com another.com          one or more hosts
botwall example.com/search?q=shoes       a real content path, not just the front door
botwall --file sites.txt                 one host per line, # for comments
botwall example.com --twice              probe twice and flag disagreement
botwall example.com --json               machine-readable
botwall --file sites.txt --concurrency 3
```

## Reading the result honestly

This is the part most tools skip, and the part that matters.

**`served` means nothing blocked at the door. It does not mean the data is
reachable.** The homepage is almost never the guarded page — it has nothing worth
guarding. A vehicle marketplace will serve you its homepage and refuse its search
results from the same protection stack. **Give the tool the URL that carries the
data**, not the domain.

**`wall: challenge` means two things had to be true at once:** the body carries
gate wording *and* the page is too small to hold anything else. A block page
returned as 200 OK is the most expensive trap in this work — it looks like success,
it passes every status check, and it fills your file with nothing. But a 300 KB page
that happens to contain the word "captcha" is not a wall, so the tool says
`served` and tells you the wording was there.

**`thin body` means the page is too small to hold content.** A homepage under
1.5 KB is a shell, a redirect stub, or a wall.

**`—` under *Guarded by* means no known signature was visible.** Not that the site
is unguarded. Some products only reveal themselves once JavaScript runs, or only on
the routes they protect. Amazon shows almost nothing in headers and is famously
hard.

**A single probe is a sample, not a property.** These systems score risk live: the
same host can pass now and be challenged in thirty seconds. Use `--twice` when the
answer matters; it runs a second pass and flags any disagreement.

**`no response` is diagnosed, not hidden.** A TLS handshake refused before any HTTP
reply is usually a fingerprint-level block — a hard target, not a dead domain. The
tool names the failure instead of calling everything "unreachable".

## What it detects

| Guard | Read from |
|---|---|
| Akamai Bot Manager | `_abck`, `ak_bmsc`, `bm_sz`, `x-akamai-reference-id`, `x-bac-akm` |
| DataDome | `x-datadome`, `datadome` cookie |
| Cloudflare Bot Management | `cf-mitigated`, `__cf_bm`, `cf-chl`, challenge-platform |
| HUMAN (PerimeterX) | `x-px-*`, `_px*` cookies, `perimeterx` |
| Imperva | `incap_ses`, `visid_incap` |
| Kasada | `x-kpsdk-*` |
| F5 | `x-distil`, `distil_ri`, `TS<hex>` cookies |
| Queue-it | `queue-it`, `queueittoken` |

CDNs are recognised separately: Akamai, Cloudflare, CloudFront, Fastly, Imperva,
AWS ELB.

## Scope

Read-only. One capped GET per host, redirects followed, nothing stored, no attempt
to defeat anything. Use it on sites you have a legitimate reason to read, at a rate
that does not disturb them.

## License

MIT — Hugo Herail
