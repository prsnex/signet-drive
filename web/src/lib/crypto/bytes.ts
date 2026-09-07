// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Byte + encoding helpers. Browser-safe: base64url uses atob/btoa (present in
// both browsers and Node), not the Node-only Buffer, so these modules run
// unchanged in the web client.
//
// `Bytes` pins the typed-array buffer to a plain ArrayBuffer (never
// SharedArrayBuffer). That is exactly what WebCrypto's BufferSource parameters
// require under TypeScript 5.7+'s generic typed arrays, so threading `Bytes`
// through the crypto signatures keeps the WebCrypto boundary cast-free.

export type Bytes = Uint8Array<ArrayBuffer>;

const TEXT_ENCODER = new TextEncoder();

/** UTF-8 encode a string to ArrayBuffer-backed `Bytes`. TextEncoder.encode's
 *  return type is not pinned to ArrayBuffer, so we normalize it here. */
export function utf8Encode(s: string): Bytes {
  return new Uint8Array(TEXT_ENCODER.encode(s));
}

export function concatBytes(...parts: Bytes[]): Bytes {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Big-endian uint32, as a 4-byte array (JOSE Concat-KDF length prefixes). */
export function u32be(n: number): Bytes {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

export function b64uDecode(s: string): Bytes {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64.length % 4 === 0 ? b64 : b64 + '='.repeat(4 - (b64.length % 4));
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64uEncode(bytes: Bytes): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function hexEncode(bytes: Bytes): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

export function hexDecode(hex: string): Bytes {
  if (hex.length % 2 !== 0) throw new Error('hex string must have even length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
