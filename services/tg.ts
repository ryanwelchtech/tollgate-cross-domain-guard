// tg: operator CLI
//   tg keygen                       create guard + lab publisher keys under keys/
//   tg pack <publisher> <files...>  build a signed transfer request (JSON) on stdout
//   tg verify-ledger <low|high>     verify the hash chain of a persisted ledger

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { b64encode, canonical, exportPrivate, generateKeyPair, importPrivate, sign } from '../core/encoding.ts';
import { makeManifest } from '../core/samples.ts';
import { verifyChain } from '../core/ledger.ts';
import { DATA, KEYS, readKey } from './common.ts';

const [cmd, ...args] = process.argv.slice(2);

async function keygen() {
  mkdirSync(join(KEYS, 'trust'), { recursive: true });
  const write = (p: string, s: string, mode: number) => writeFileSync(join(KEYS, p), s + '\n', { mode });
  if (!existsSync(join(KEYS, 'guard.key'))) {
    const g = await generateKeyPair();
    write('guard.key', await exportPrivate(g.privateKey), 0o600);
    write('guard.pub', g.publicRaw, 0o644);
    console.log('guard key pair      -> keys/guard.{key,pub}');
  }
  const pubId = args[0] ?? 'lab-release-eng';
  if (!existsSync(join(KEYS, `${pubId}.key`))) {
    const p = await generateKeyPair();
    write(`${pubId}.key`, await exportPrivate(p.privateKey), 0o600);
    write(`trust/${pubId}.pub`, p.publicRaw, 0o644);
    console.log(`publisher key pair  -> keys/${pubId}.key, keys/trust/${pubId}.pub`);
  }
}

async function pack() {
  const [publisher, ...paths] = args;
  const requester = process.env.TG_USER ?? 'j.ramirez';
  const files = paths.map((p) => ({ name: basename(p), bytes: new Uint8Array(readFileSync(p)) }));
  const manifest = await makeManifest(files, requester, publisher, process.env.TG_JUSTIFICATION ?? 'operator submission');
  const key = await importPrivate(readKey(`${publisher}.key`));
  const signature = await sign(key, canonical(manifest));
  process.stdout.write(JSON.stringify({ manifest, signature, files: files.map((f) => ({ name: f.name, b64: b64encode(f.bytes) })) }));
}

async function verifyLedger() {
  const side = args[0] === 'high' ? 'highside' : 'lowside';
  const file = join(DATA, side, 'ledger.jsonl');
  const entries = readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const r = await verifyChain(entries);
  console.log(r.ok ? `OK  ${entries.length} entries, head ${entries.at(-1)?.hash ?? '(empty)'}` : `BROKEN at entry ${r.brokenAt}: ${r.reason}`);
  process.exit(r.ok ? 0 : 1);
}

const cmds: Record<string, () => Promise<void>> = { keygen, pack, 'verify-ledger': verifyLedger };
if (!cmds[cmd]) {
  console.error('usage: tg keygen [publisher] | tg pack <publisher> <files...> | tg verify-ledger <low|high>');
  process.exit(64);
}
await cmds[cmd]();
