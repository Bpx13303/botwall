#!/usr/bin/env node
/**
 * botwall — who delivers this site, who guards it, and what a plain request gets.
 *
 * One capped GET per host (first 4 KB), redirects followed.
 * It reads the response headers and the start of the body, names the CDN and the
 * bot-management product separately, and reports what it can actually prove.
 * It does not bypass anything.
 */
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { promisify } from 'node:util';
import { domainToASCII } from 'node:url';

const run = promisify(execFile);

const UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

/* ── who delivers the site ─────────────────────────────────────────────── */
const CDNS = [
  { name: 'Akamai',     test: /akamaighost|akamainetstorage|x-akamai|aka(cd|as|vpau)_|server-timing:[^\n]*ak_p/i },
  { name: 'Cloudflare', test: /cf-ray|server:\s*cloudflare/i },
  { name: 'CloudFront', test: /x-amz-cf-id|via:[^\n]*cloudfront|server:\s*cloudfront/i },
  { name: 'Fastly',     test: /fastly|x-fastly/i },
  { name: 'Imperva',    test: /x-iinfo|x-cdn:\s*incapsula/i },
  { name: 'AWS ELB',    test: /awselb/i },
];

/* ── who guards it: only signals that mean active bot management ───────── */
const GUARDS = [
  { name: 'Akamai Bot Manager', test: /_abck|ak_bmsc|bm_sz|x-akamai-reference-id|x-bac-akm|akm-c:\s*on/i },
  { name: 'DataDome',           test: /x-datadome|datadome=|set-cookie:[^\n]*datadome/i },
  { name: 'Cloudflare Bot Mgmt',test: /cf-mitigated|__cf_bm|cf-chl|challenge-platform/i },
  { name: 'HUMAN (PerimeterX)', test: /x-px-|_px[a-z]{0,4}=|perimeterx|px-cloud/i },
  { name: 'Imperva Advanced',   test: /incap_ses|visid_incap|x-iinfo:[^\n]*incap/i },
  { name: 'Kasada',             test: /x-kpsdk/i },
  { name: 'F5',                 test: /x-distil|distil_ri|shape-security|set-cookie:\s*TS[0-9a-f]{6,}=/i },
  { name: 'Queue-it',           test: /queue-it|queueittoken/i },
];

/* ── what a wall looks like in the first bytes of the body ─────────────── */
const WALL_HINTS = [
  { name: 'challenge', test: /challenge-platform|are you human|verify you are|captcha|_Incapsula_Resource|sorry[_-]?server|access denied|zugriff verweigert/i },
  { name: 'login',     test: /<form[^>]+(login|signin)|please (log|sign) in|connectez-vous/i },
];

/** curl exit codes worth naming instead of hiding behind "unreachable" */
const CURL_ERRORS = {
  6:  'DNS: host not found',
  7:  'connection refused',
  28: 'timeout',
  35: 'TLS handshake refused',        // often a fingerprint-level block
  47: 'too many redirects',
  56: 'connection reset mid-transfer',
  60: 'TLS certificate problem',
  92: 'HTTP/2 stream error',          // response usually still complete
};

function toURL(input) {
  const raw = String(input).trim();
  if (!raw) return null;
  const withScheme = /^https?:\/\//i.test(raw) ? raw : 'https://' + raw;
  try {
    const u = new URL(withScheme);
    u.hostname = domainToASCII(u.hostname) || u.hostname;   // IDN -> punycode
    return u;
  } catch { return null; }
}

function identify(raw) {
  const cdn = CDNS.filter(c => c.test.test(raw)).map(c => c.name);
  const guard = GUARDS.filter(g => g.test.test(raw)).map(g => g.name);
  return { cdn: cdn.join(' + ') || '—', guard: guard.join(' + ') || '—' };
}

function readVerdict({ status, bytes, guard, body, effective, asked }) {
  const wall = WALL_HINTS.find(w => w.test.test(body));
  if (status === 401 || status === 403) return { verdict: 'refused', why: `HTTP ${status}` };
  if (status === 429) return guard !== '—'
    ? { verdict: 'challenged', why: '429 alongside a bot-management signal' }
    : { verdict: 'rate-limited', why: 'HTTP 429' };
  if (status === 503) return { verdict: 'challenged', why: 'HTTP 503' };
  if (status === 405 || status === 404) return { verdict: 'method refused', why: `HTTP ${status} — retry with a browser` };
  if (status >= 400) return { verdict: 'refused', why: `HTTP ${status}` };
  if (status >= 200 && status < 300) {   // 206 = our own range request, not a site behaviour
    if (wall) return { verdict: `wall: ${wall.name}`, why: 'body looks like a gate, not content' };
    if (bytes > 0 && bytes < 1500) return { verdict: 'thin body', why: `${bytes} B page — too small to hold content` };
    const bare = h => String(h).replace(/^www\./i, '').toLowerCase();
    if (effective && asked && bare(new URL(effective).hostname) !== bare(asked))
      return { verdict: 'served, other host', why: `answered by ${new URL(effective).hostname}` };
    return { verdict: 'served', why: 'nothing blocked at the door' };
  }
  return { verdict: 'unclear', why: `HTTP ${status}` };
}

async function probeOnce(url) {
  const args = [
    '-sL', '-i', '-r', '0-4095', '--max-time', '20',
    '-A', UA,
    '-H', 'Accept-Language: en-US,en;q=0.9',
    url.toString(),
    '-w', '\nBOTWALL|%{http_code}|%{size_download}|%{url_effective}',
  ];
  try {
    const { stdout } = await run('curl', args, { maxBuffer: 2e7 });
    return { stdout, err: null };
  } catch (e) {
    // curl can fail late (HTTP/2 stream errors) with a perfectly good response
    return { stdout: String(e.stdout || ''), err: e };
  }
}

async function probe(input) {
  const url = toURL(input);
  if (!url) return { host: String(input).trim(), status: null, cdn: '—', guard: '—', verdict: 'invalid host' };

  const { stdout, err } = await probeOnce(url);
  const meta = stdout.match(/BOTWALL\|(\d+)\|(\d+)\|(\S*)/);

  if (!meta || !Number(meta[1])) {
    const code = err?.code;
    return {
      host: url.hostname,
      status: null,
      cdn: '—', guard: '—',
      verdict: 'no response',
      why: CURL_ERRORS[code] || (code ? `curl exit ${code}` : 'no reply'),
      ...(code === 35 ? { hint: 'refused before HTTP — often a TLS-fingerprint block' } : {}),
    };
  }

  const status = Number(meta[1]);
  const downloaded = Number(meta[2]);
  // real page size: Content-Range total, else Content-Length, else what we got
  const range = stdout.match(/content-range:\s*bytes\s+\d+-\d+\/(\d+)/i);
  const len = stdout.match(/content-length:\s*(\d+)/i);
  const bytes = range ? Number(range[1]) : (len && downloaded >= 4096 ? Number(len[1]) : downloaded);
  const effective = meta[3];
  const headEnd = stdout.lastIndexOf('\r\n\r\n');
  const body = headEnd > -1 ? stdout.slice(headEnd, stdout.indexOf('\nBOTWALL|')) : '';
  const { cdn, guard } = identify(stdout);
  const { verdict, why } = readVerdict({ status, bytes, guard, body, effective, asked: url.hostname });

  return {
    host: url.hostname,
    status, cdn, guard, verdict, why, bytes, downloaded,
    ...(effective && new URL(effective).hostname.replace(/^www\./i, '') !== url.hostname.replace(/^www\./i, '') ? { effective } : {}),
    ...(err ? { note: `curl exit ${err.code} (${CURL_ERRORS[err.code] || 'late failure'}) — response read anyway` } : {}),
  };
}

/* ── CLI ───────────────────────────────────────────────────────────────── */
function parseArgs(argv) {
  const out = { hosts: [], json: false, concurrency: 5, twice: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') out.json = true;
    else if (a === '--twice') out.twice = true;
    else if (a === '--file') {
      const p = argv[++i];
      try {
        out.hosts.push(...readFileSync(p, 'utf8').split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#')));
      } catch (e) { console.error(`botwall: cannot read --file ${p}: ${e.code || e.message}`); process.exit(1); }
    }
    else if (a === '--concurrency') {
      const n = Number(argv[++i]);
      if (!Number.isFinite(n) || n < 1) { console.error('botwall: --concurrency needs a positive number'); process.exit(1); }
      out.concurrency = n;
    }
    else if (a === '--help' || a === '-h') out.help = true;
    else out.hosts.push(a.trim());
  }
  return out;
}

async function pool(items, size, worker) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, async () => {
    while (next < items.length) { const i = next++; results[i] = await worker(items[i]); }
  }));
  return results;
}

const args = parseArgs(process.argv.slice(2));

if (args.help || !args.hosts.length) {
  console.log(`botwall — who delivers this site, who guards it, what a plain request gets

  botwall example.com                     one or more hosts
  botwall example.com/search?q=x          a real content path, not just the door
  botwall --file sites.txt                one host per line, # for comments
  botwall example.com --twice             probe twice: bot scoring is live, one sample proves little
  botwall example.com --json              machine-readable
  botwall --file sites.txt --concurrency 3

One capped GET per host (first 4 KB), redirects followed. Reads headers and the
start of the body. Names the CDN and the bot-management product separately,
because they are not the same thing. It does not bypass anything.`);
  process.exit(args.help ? 0 : 1);
}

let rows = await pool(args.hosts, args.concurrency, probe);

if (args.twice) {
  await new Promise(r => setTimeout(r, 2500));
  const again = await pool(args.hosts, args.concurrency, probe);
  rows = rows.map((r, i) => {
    const b = again[i];
    const same = r.status === b.status && r.guard === b.guard && r.verdict === b.verdict;
    return same ? r : { ...r, unstable: `second probe: ${b.status} ${b.guard} ${b.verdict}` };
  });
}

if (args.json) {
  console.log(JSON.stringify(rows, null, 2));
} else {
  const w = (k, min) => Math.max(min, ...rows.map(r => String(r[k] ?? '—').length));
  const [wh, wc, wg] = [w('host', 4), w('cdn', 9), w('guard', 15)];
  console.log('HOST'.padEnd(wh), 'CODE'.padEnd(4), 'DELIVERED BY'.padEnd(wc), 'GUARDED BY'.padEnd(wg), 'PLAIN REQUEST');
  console.log('-'.repeat(wh), '-'.repeat(4), '-'.repeat(wc), '-'.repeat(wg), '-'.repeat(13));
  for (const r of rows) {
    console.log(
      String(r.host).padEnd(wh),
      String(r.status ?? '—').padEnd(4),
      String(r.cdn).padEnd(wc),
      String(r.guard).padEnd(wg),
      r.verdict + (r.why ? `  (${r.why})` : '')
    );
    if (r.effective) console.log(' '.repeat(wh + 2) + `↳ answered by ${r.effective}`);
    if (r.unstable) console.log(' '.repeat(wh + 2) + `↳ unstable — ${r.unstable}`);
    if (r.note)     console.log(' '.repeat(wh + 2) + `↳ ${r.note}`);
  }
}

// non-zero if nothing at all came back
process.exit(rows.every(r => r.status === null) ? 1 : 0);
