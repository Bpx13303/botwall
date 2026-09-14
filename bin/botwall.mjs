#!/usr/bin/env node
/**
 * botwall — tells you which bot protection a site runs, and whether a plain request gets through.
 *
 * Read-only reconnaissance: one HEAD request per host, following redirects.
 * It identifies a protection from response headers and cookies. It does not
 * bypass anything, and it does not touch a site's content.
 */
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { promisify } from 'node:util';

const run = promisify(execFile);

const UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

/** Header and cookie fingerprints, most specific first. */
const SIGNATURES = [
  { name: 'Akamai',      test: /_abck|ak_bmsc|bm_sz|x-akamai|akamaighost/ },
  { name: 'DataDome',    test: /datadome|x-datadome/ },
  { name: 'Cloudflare',  test: /cf-ray|__cf_bm|cf-mitigated|server:\s*cloudflare/ },
  { name: 'HUMAN',       test: /_px[a-z0-9]*=|perimeterx|px-cloud/ },
  { name: 'Imperva',     test: /incap_ses|visid_incap|x-iinfo|x-cdn:\s*incapsula/ },
  { name: 'Kasada',      test: /x-kpsdk|kpsdk/ },
  { name: 'F5 Shape',    test: /x-distil|distil_ri|shape-/ },
  { name: 'Queue-it',    test: /queue-it|queueittoken/ },
  { name: 'Fastly',      test: /x-served-by|fastly/ },
  { name: 'AWS edge',    test: /x-amz-cf-id|awselb|x-amzn-requestid/ },
];

const VERDICTS = {
  200: 'passes',
  204: 'passes',
  401: 'refused',
  403: 'refused',
  405: 'HEAD not allowed',   // not a block: the site simply refuses this method
  429: 'rate-limited',
  503: 'challenged',
};

function identify(raw) {
  const h = raw.toLowerCase();
  const hits = SIGNATURES.filter(s => s.test.test(h)).map(s => s.name);
  return hits.length ? hits.join(' + ') : '—';
}

async function probe(host) {
  const url = host.startsWith('http') ? host : `https://${host}/`;
  try {
    const { stdout } = await run('curl', [
      '-sIL', '-m', '20',
      '-A', UA,
      '-H', 'Accept-Language: en-US,en;q=0.9',
      url,
      '-w', '\nSTATUS:%{http_code} BYTES:%{size_download}',
    ], { maxBuffer: 8e6 });

    const status = (stdout.match(/STATUS:(\d+)/) || [])[1] || '?';
    const bytes  = (stdout.match(/BYTES:(\d+)/) || [])[1] || '';
    return {
      host,
      status: Number(status) || null,
      protection: identify(stdout),
      plainRequest: VERDICTS[status] || (status >= 400 ? 'refused' : 'unclear'),
      note: status === '405' ? 'retry with GET to know whether the content is reachable' : undefined,
      bytes: Number(bytes) || 0,
    };
  } catch (err) {
    return {
      host,
      status: null,
      protection: identify(String(err.stdout || '')),
      plainRequest: 'unreachable',
      bytes: 0,
    };
  }
}

function parseArgs(argv) {
  const out = { hosts: [], json: false, concurrency: 5 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') out.json = true;
    else if (a === '--file') out.hosts.push(...readFileSync(argv[++i], 'utf8').split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#')));
    else if (a === '--concurrency') out.concurrency = Number(argv[++i]) || 5;
    else if (a === '--help' || a === '-h') out.help = true;
    else out.hosts.push(a);
  }
  return out;
}

async function pool(items, size, worker) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(size, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        results[i] = await worker(items[i]);
      }
    })
  );
  return results;
}

const args = parseArgs(process.argv.slice(2));

if (args.help || !args.hosts.length) {
  console.log(`botwall — which bot protection is this site running?

  botwall example.com shop.example.com
  botwall --file sites.txt
  botwall example.com --json

  --file <path>         one host per line, # for comments
  --json                machine-readable output
  --concurrency <n>     parallel probes (default 5)

One HEAD request per host. Identifies the protection from headers and cookies,
and reports what a plain request gets back. It does not bypass anything.`);
  process.exit(args.help ? 0 : 1);
}

const rows = await pool(args.hosts, args.concurrency, probe);

if (args.json) {
  console.log(JSON.stringify(rows, null, 2));
} else {
  const w = Math.max(4, ...rows.map(r => r.host.length));
  console.log('HOST'.padEnd(w), 'CODE'.padEnd(5), 'PROTECTION'.padEnd(22), 'PLAIN REQUEST');
  console.log('-'.repeat(w), '-'.repeat(5), '-'.repeat(22), '-'.repeat(13));
  for (const r of rows) {
    console.log(
      r.host.padEnd(w),
      String(r.status ?? '—').padEnd(5),
      r.protection.padEnd(22),
      r.plainRequest
    );
  }
}
