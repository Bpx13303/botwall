# botwall

**Which bot protection is this site running, and does a plain request get through?**

One HEAD request per host. It reads the response headers and cookies, names the
protection behind the site, and tells you what a plain request gets back.

It does not bypass anything. It tells you what you are up against before you
write a single line of scraper.

```
$ npx botwall www.example-shop.fr www.example-store.com

HOST                  CODE  PROTECTION             PLAIN REQUEST
--------------------- ----- ---------------------- -------------
www.example-shop.fr   403   Cloudflare             refused
www.example-store.com 200   Akamai                 passes
```

## Why it exists

Most scraping projects fail for a reason that could have been known in ten
seconds: the target sits behind a protection the tooling was never going to get
past. Quoting a job, or accepting one, without knowing that is how a two-day
project becomes a two-week one.

This is the first thing I run when someone sends me a URL.

## Install

Requires Node 18+ and `curl` (present on macOS and most Linux distributions).

```bash
npx botwall example.com
```

Or clone it:

```bash
git clone https://github.com/Bpx13303/botwall.git
cd botwall
node bin/botwall.mjs example.com
```

## Usage

```bash
botwall example.com shop.example.com      # one or more hosts
botwall --file sites.txt                  # one host per line, # for comments
botwall example.com --json                # machine-readable
botwall --file sites.txt --concurrency 3  # default is 5
```

### JSON output

```json
[
  {
    "host": "www.example-shop.fr",
    "status": 403,
    "protection": "Cloudflare",
    "plainRequest": "refused",
    "bytes": 0
  }
]
```

## What it detects

| Protection | Read from |
|---|---|
| Akamai | `_abck`, `ak_bmsc`, `bm_sz`, `x-akamai-*`, `AkamaiGHost` |
| DataDome | `datadome` cookie, `x-datadome` |
| Cloudflare | `cf-ray`, `__cf_bm`, `cf-mitigated`, `server: cloudflare` |
| HUMAN (PerimeterX) | `_px*` cookies, `perimeterx`, `px-cloud` |
| Imperva (Incapsula) | `incap_ses`, `visid_incap`, `x-iinfo` |
| Kasada | `x-kpsdk-*` |
| F5 Shape (Distil) | `x-distil`, `distil_ri` |
| Queue-it | `queue-it`, `queueittoken` |
| Fastly / AWS edge | `x-served-by`, `x-amz-cf-id`, `awselb` |

## Reading the result honestly

**`passes` does not mean the data is reachable.** A HEAD request on the homepage
is the cheapest possible probe, and plenty of sites let it through while
refusing the pages that actually carry content. Treat `passes` as *nothing
blocked me at the door*, not as *this site is open*.

**`—` does not mean unprotected.** Some products only reveal themselves once
JavaScript runs, or only on the routes they are configured to guard. An empty
result means nothing was visible in the headers of that one response.

**A protection is not a verdict.** Every site listed above is a normal site
serving public pages. Knowing which product guards the door tells you how to
approach it politely — at what rate, with what client — not that you should
force it.

## Scope

Read-only. One HEAD request per host, redirects followed, nothing stored,
no content fetched, no attempt to defeat anything. Use it on sites you have a
legitimate reason to read, at a rate that does not disturb them.

## License

MIT — Hugo Herail
