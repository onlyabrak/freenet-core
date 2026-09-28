// Executable unit test for the shell's PASSKEY bridge (#5764) in
// `path_handlers/assets/shell_bridge.js`.
//
// The block runs in the browser shell, whose IIFE touches browser-only globals,
// so — like shell_bridge_notifications.test.mjs — this EXTRACTS it verbatim
// (between the `passkey:BEGIN`/`:END` markers) and drives it with stubbed
// globals. It checks what a source pin cannot:
//   - the PRF input is SHA-256("freenet shell passkey\0" + contract + "\0" +
//     salt), computed here independently — never the app's raw salt (the
//     binding that keeps one contract from obtaining another's secret);
//   - the contract comes from the server-routed PATH, not from the message;
//   - an IP host is refused (not a relying-party id), a malformed request too;
//   - WebAuthn runs only from the shell's own Continue click; one bar at a time;
//     Cancel answers `dismissed`.
// The real-browser behaviour (the sandboxed frame reaching the bridge, the bar
// drawn by the shell) is the Playwright test's.
//
// Run via `npm test` in crates/core/src/server. Exits non-zero on any mismatch.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { webcrypto } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(
  join(here, 'path_handlers/assets/shell_bridge.js'),
  'utf8',
);
const b = src.indexOf('passkey:BEGIN');
const e = src.indexOf('passkey:END');
if (b < 0 || e < 0 || e < b) {
  console.error('FAIL: passkey:BEGIN/END markers not found in shell_bridge.js');
  process.exit(1);
}
const block = src.slice(src.indexOf('\n', b) + 1, e);

let failures = 0;
const check = (ok, what) => {
  if (!ok) {
    failures += 1;
    console.error(`FAIL: ${what}`);
  } else console.log(`ok: ${what}`);
};
const hex = (u) =>
  [...new Uint8Array(u)].map((x) => x.toString(16).padStart(2, '0')).join('');
const tick = () => new Promise((r) => setTimeout(r, 0));

// A shell at `pathname` on `hostname`: the block evaluated against stubs.
function shell({
  hostname = 'localhost',
  pathname = '/v1/contract/web/CONTRACTA/',
  credentials,
} = {}) {
  const sent = [];
  const body = {
    kids: [],
    appendChild(n) {
      this.kids.push(n);
    },
    removeChild(n) {
      this.kids = this.kids.filter((k) => k !== n);
    },
  };
  const element = () => ({
    style: {},
    handlers: {},
    kids: [],
    textContent: '',
    disabled: false,
    setAttribute() {},
    appendChild(n) {
      this.kids.push(n);
    },
    addEventListener(t, f) {
      this.handlers[t] = f;
    },
  });
  const calls = [];
  const creds = credentials ?? {
    create: async (o) => (
      calls.push(['create', o]),
      {
        rawId: new Uint8Array([1, 2, 3]).buffer,
        getClientExtensionResults: () => ({
          prf: {
            enabled: true,
            results: { first: new Uint8Array(32).fill(7).buffer },
          },
        }),
      }
    ),
    get: async (o) => (
      calls.push(['get', o]),
      {
        rawId: new Uint8Array([1, 2, 3]).buffer,
        getClientExtensionResults: () => ({
          prf: { results: { first: new Uint8Array(32).fill(9).buffer } },
        }),
      }
    ),
  };
  const env = {
    location: { hostname, pathname },
    document: { createElement: element, body },
    navigator: { credentials: creds },
    window: { crypto: webcrypto },
    crypto: webcrypto,
    PublicKeyCredential: function () {},
    TextEncoder,
    sendToIframe: (m) => sent.push(m),
  };
  const f = new Function(
    ...Object.keys(env),
    `${block}\nreturn { passkeyRequest, passkeyBoundSalt };`,
  );
  const api = f(...Object.values(env));
  const bar = () => body.kids[body.kids.length - 1];
  const button = (label) => bar()?.kids.find((k) => k.textContent === label);
  return { api, sent, calls, body, bar, button };
}

const salt = new Uint8Array(32).fill(0x5a);
const expectBound = async (contract) => {
  const head = new TextEncoder().encode(`freenet shell passkey\0${contract}\0`);
  const all = new Uint8Array(head.length + 32);
  all.set(head);
  all.set(salt, head.length);
  return hex(await webcrypto.subtle.digest('SHA-256', all));
};

// 1. Malformed requests and an IP host are refused, with no bar shown.
{
  const s = shell();
  s.api.passkeyRequest({ id: 'a', op: 'steal', salt });
  s.api.passkeyRequest({ id: 'b', op: 'get', salt: new Uint8Array(16) });
  s.api.passkeyRequest({
    id: 'c',
    op: 'get',
    salt,
    credential: new Uint8Array(0),
  });
  check(
    s.sent.map((m) => m.error).join() === 'bad_request,bad_request,bad_request',
    'malformed requests are bad_request',
  );
  check(s.body.kids.length === 0, 'no bar for a malformed request');
  const ip = shell({ hostname: '127.0.0.1' });
  ip.api.passkeyRequest({ id: 'd', op: 'get', salt });
  check(
    ip.sent[0]?.error === 'unsupported' && ip.body.kids.length === 0,
    'an IP host is unsupported (not a relying-party id)',
  );
}

// 2. create: only the shell's Continue click runs WebAuthn; the PRF input is
//    the contract-bound hash of the salt, the contract from the PATH (the
//    message's `contract` field is ignored), never the raw salt.
{
  const s = shell({ pathname: '/v1/contract/web/CONTRACTA/index.html' });
  s.api.passkeyRequest({
    id: 'x',
    op: 'create',
    salt,
    contract: 'CONTRACTB',
    name: 'me',
  });
  check(
    s.calls.length === 0 && s.sent.length === 0,
    'nothing runs before the click',
  );
  check(
    /contract CONTRACT/.test(s.bar().kids[0].textContent),
    'the bar names the contract',
  );
  s.button('Continue').handlers.click();
  for (let i = 0; i < 5; i++) await tick();
  const [op, opts] = s.calls[0] ?? [];
  check(
    op === 'create' && opts.publicKey.rp.id === 'localhost',
    'create runs with rp id = the host',
  );
  const input = hex(opts.publicKey.extensions.prf.eval.first);
  check(
    input === (await expectBound('CONTRACTA')),
    'PRF input = SHA-256(label ‖ path contract ‖ salt)',
  );
  check(input !== hex(salt), 'PRF input is never the raw salt');
  check(
    input !== (await expectBound('CONTRACTB')),
    "the message's contract field is ignored",
  );
  const r = s.sent[0];
  check(
    r?.ok === true && r.id === 'x' && r.prf?.byteLength === 32 && r.credential,
    'create answers ok with the PRF output and credential id',
  );
  check(s.body.kids.length === 0, 'the bar is gone after answering');
}

// 3. Two contracts, one salt: different PRF inputs (no cross-contract secret).
{
  const a = await shell({
    pathname: '/v1/contract/web/AAA/',
  }).api.passkeyBoundSalt('AAA', salt);
  const bb = await shell({
    pathname: '/v1/contract/web/BBB/',
  }).api.passkeyBoundSalt('BBB', salt);
  check(
    hex(a) !== hex(bb),
    'different contracts get different PRF inputs for the same salt',
  );
}

// 4. get: allowCredentials from the message; one bar at a time; Cancel.
{
  const s = shell();
  s.api.passkeyRequest({
    id: 'g1',
    op: 'get',
    salt,
    credential: new Uint8Array([1, 2, 3]),
  });
  s.api.passkeyRequest({ id: 'g2', op: 'get', salt });
  check(
    s.sent[0]?.id === 'g2' && s.sent[0].error === 'busy',
    'a second request while one is shown is busy',
  );
  s.button('Continue').handlers.click();
  for (let i = 0; i < 5; i++) await tick();
  const [, opts] = s.calls[0] ?? [];
  check(
    opts?.publicKey.allowCredentials?.[0]?.id?.byteLength === 3,
    'get passes the credential id as allowCredentials',
  );
  check(
    s.sent[1]?.ok === true && s.sent[1].prf.byteLength === 32,
    'get answers the PRF output',
  );
  const c = shell();
  c.api.passkeyRequest({ id: 'c1', op: 'get', salt });
  c.button('Cancel').handlers.click();
  check(
    c.sent[0]?.error === 'dismissed' &&
      c.calls.length === 0 &&
      c.body.kids.length === 0,
    'Cancel answers dismissed, runs nothing',
  );
}

// 5. A WebAuthn failure is answered, and the next request is not stuck busy.
{
  const s = shell({
    credentials: {
      create: async () => {
        throw Object.assign(new Error('no'), { name: 'NotAllowedError' });
      },
      get: async () => null,
    },
  });
  s.api.passkeyRequest({ id: 'f', op: 'create', salt });
  s.button('Continue').handlers.click();
  for (let i = 0; i < 5; i++) await tick();
  check(
    s.sent[0]?.error === 'NotAllowedError' && s.body.kids.length === 0,
    'a refused prompt answers its error',
  );
}

if (failures) {
  console.error(`${failures} check(s) failed`);
  process.exit(1);
}
console.log('shell_bridge_passkey: all checks passed');
