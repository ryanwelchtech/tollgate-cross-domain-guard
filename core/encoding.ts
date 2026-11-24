// Small portable helpers: hashing, base64, canonical JSON, Ed25519 via WebCrypto.
// WebCrypto (globalThis.crypto.subtle) exists in Node >= 20 and all modern browsers.

const subtle = globalThis.crypto.subtle;

export const te = new TextEncoder();
export const td = new TextDecoder('utf-8', { fatal: false });

export function toHex(buf: ArrayBuffer | Uint8Array): string {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

export async function sha256(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === 'string' ? te.encode(data) : data;
  return toHex(await subtle.digest('SHA-256', bytes as BufferSource));
}

export function b64encode(bytes: Uint8Array): string {
  let bin = '';
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CH));
  }
  return btoa(bin);
}

export function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Deterministic JSON: object keys sorted recursively. Used for anything signed or hashed. */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}';
}

export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicRaw: string; // base64
}

export async function generateKeyPair(): Promise<KeyPair> {
  const kp = (await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const raw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  return { publicKey: kp.publicKey, privateKey: kp.privateKey, publicRaw: b64encode(raw) };
}

export async function exportPrivate(key: CryptoKey): Promise<string> {
  return b64encode(new Uint8Array(await subtle.exportKey('pkcs8', key)));
}

export async function importPrivate(pkcs8b64: string): Promise<CryptoKey> {
  return subtle.importKey('pkcs8', b64decode(pkcs8b64) as BufferSource, { name: 'Ed25519' }, false, ['sign']);
}

export async function importPublic(rawb64: string): Promise<CryptoKey> {
  return subtle.importKey('raw', b64decode(rawb64) as BufferSource, { name: 'Ed25519' }, true, ['verify']);
}

export async function sign(privateKey: CryptoKey, message: string): Promise<string> {
  const sig = await subtle.sign({ name: 'Ed25519' }, privateKey, te.encode(message));
  return b64encode(new Uint8Array(sig));
}

export async function verify(publicRawB64: string, message: string, sigB64: string): Promise<boolean> {
  try {
    const key = await importPublic(publicRawB64);
    return await subtle.verify({ name: 'Ed25519' }, key, b64decode(sigB64) as BufferSource, te.encode(message));
  } catch {
    return false;
  }
}

export function extname(name: string): string {
  const base = name.split('/').pop() ?? name;
  const multi = base.match(/(\.cdx\.json|\.tar\.gz)$/i);
  if (multi) return multi[1].toLowerCase();
  const i = base.lastIndexOf('.');
  return i <= 0 ? '' : base.slice(i).toLowerCase();
}

let crcTable: Uint32Array | null = null;
export function crc32(data: Uint8Array): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) crc = crcTable[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
