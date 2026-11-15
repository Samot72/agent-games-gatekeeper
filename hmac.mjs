import { createHmac, timingSafeEqual } from 'node:crypto';

export const SIGNATURE_HEADER = 'x-agent-games-signature';

// The dashboard shows the HMAC secret once as text. It is undocumented whether
// the key is the text's UTF-8 bytes or the hex-decoded 32 bytes, so accept
// whichever the inbound signature proves and sign back with that same key.
export function candidateKeys(secret) {
  if (!secret) return [];
  const keys = [Buffer.from(secret, 'utf8')];
  if (/^[0-9a-fA-F]{64}$/.test(secret.trim())) keys.push(Buffer.from(secret.trim(), 'hex'));
  return keys;
}

export function signHex(key, body) {
  return createHmac('sha256', key).update(body).digest('hex');
}

// Returns the key that produced `header` over the raw body, or null.
export function verifyKey(keys, rawBody, header) {
  if (!header || typeof header !== 'string') return null;
  const given = header.trim().replace(/^sha256=/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(given)) return null;
  const givenBytes = Buffer.from(given, 'hex');
  for (const key of keys) {
    const expected = Buffer.from(signHex(key, rawBody), 'hex');
    if (timingSafeEqual(expected, givenBytes)) return key;
  }
  return null;
}
