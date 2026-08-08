/**
 * Environment-safe crypto and encoding utilities.
 * Works in browsers, Node.js, and edge runtimes (Vercel, Cloudflare, etc.)
 */

// ── Base64url ──────────────────────────────────────────────

export function base64urlEncode(bytes: Uint8Array): string {
  // Browser path
  if (typeof btoa === 'function') {
    let str = '';
    for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  // Node.js path
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64url');
  }
  throw new Error('No base64 implementation available');
}

// ── Random bytes ───────────────────────────────────────────

function getCrypto(): Crypto {
  // Browser / Edge: global crypto
  if (typeof crypto !== 'undefined' && crypto.subtle) return crypto;
  // Node 18+: globalThis.crypto is available
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    return globalThis.crypto;
  }
  throw new Error('Web Crypto API not available in this environment');
}

export function randomBytes(length: number): Uint8Array {
  const c = getCrypto();
  const arr = new Uint8Array(length);
  c.getRandomValues(arr);
  return arr;
}

export function randomString(length: number = 32): string {
  return base64urlEncode(randomBytes(length));
}

// ── SHA-256 ────────────────────────────────────────────────

export async function sha256(data: string): Promise<Uint8Array> {
  const c = getCrypto();
  const encoded = new TextEncoder().encode(data);
  const hash = await c.subtle.digest('SHA-256', encoded);
  return new Uint8Array(hash);
}