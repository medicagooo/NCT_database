import type { EncryptedEnvelope, JsonObject, RsaOaepEncryptedEnvelope } from '../../shared/types';
import { stableStringify } from './json';

const encoder = new TextEncoder();

function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  return view.buffer.slice(
    view.byteOffset,
    view.byteOffset + view.byteLength,
  ) as ArrayBuffer;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function readPemBody(value: string): string {
  return String(value || '')
    .trim()
    .replace(/\\n/g, '\n')
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
}

function bytesToPem(bytes: Uint8Array, label: string): string {
  const base64 = bytesToBase64(bytes);
  const chunks = base64.match(/.{1,64}/g) ?? [];

  return [
    `-----BEGIN ${label}-----`,
    ...chunks,
    `-----END ${label}-----`,
  ].join('\n');
}

async function importAesKey(
  secret: string,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  const rawKey = base64ToBytes(secret);
  if (rawKey.byteLength !== 32) {
    throw new Error('ENCRYPTION_KEY must be a base64-encoded 32-byte value.');
  }

  return crypto.subtle.importKey(
    'raw',
    toArrayBuffer(rawKey),
    { name: 'AES-GCM' },
    false,
    usages,
  );
}

async function importRsaEncryptionPublicKey(
  publicKey: string,
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'spki',
    toArrayBuffer(base64ToBytes(readPemBody(publicKey))),
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    false,
    ['encrypt'],
  );
}

async function importRsaEncryptionPrivateKey(
  privateKey: string,
  extractable = false,
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'pkcs8',
    toArrayBuffer(base64ToBytes(readPemBody(privateKey))),
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    extractable,
    ['decrypt'],
  );
}

export async function sha256(
  value: string,
): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    toArrayBuffer(encoder.encode(value)),
  );

  return Array.from(new Uint8Array(digest))
    .map((chunk) => chunk.toString(16).padStart(2, '0'))
    .join('');
}

export async function encryptObject(
  payload: JsonObject,
  secret: string,
): Promise<EncryptedEnvelope> {
  const key = await importAesKey(secret, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(stableStringify(payload));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
    },
    key,
    toArrayBuffer(plaintext),
  );

  return {
    algorithm: 'AES-GCM',
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

export async function decryptObject(
  envelope: EncryptedEnvelope,
  secret: string,
): Promise<JsonObject> {
  const key = await importAesKey(secret, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(base64ToBytes(envelope.iv)),
    },
    key,
    toArrayBuffer(base64ToBytes(envelope.ciphertext)),
  );

  return JSON.parse(new TextDecoder().decode(new Uint8Array(plaintext))) as JsonObject;
}

export async function deriveEncryptionPublicKeyFromPrivateKey(
  privateKey: string,
): Promise<string> {
  const importedPrivateKey = await importRsaEncryptionPrivateKey(privateKey, true);
  const exportedJwk = await crypto.subtle.exportKey(
    'jwk',
    importedPrivateKey,
  ) as JsonWebKey;

  if (
    exportedJwk.kty !== 'RSA'
    || typeof exportedJwk.n !== 'string'
    || typeof exportedJwk.e !== 'string'
  ) {
    throw new Error('SERVICE_ENCRYPTION_PRIVATE_KEY is not a valid RSA private key.');
  }

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    {
      alg: 'RSA-OAEP-256',
      e: exportedJwk.e,
      ext: true,
      key_ops: ['encrypt'],
      kty: 'RSA',
      n: exportedJwk.n,
    },
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    true,
    ['encrypt'],
  );
  const spki = await crypto.subtle.exportKey('spki', publicKey) as ArrayBuffer;

  return bytesToPem(new Uint8Array(spki), 'PUBLIC KEY');
}

export async function encryptJsonWithPublicKey(
  value: unknown,
  publicKey: string,
): Promise<RsaOaepEncryptedEnvelope> {
  const aesKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const contentKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(aesKey),
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
    },
    contentKey,
    toArrayBuffer(encoder.encode(stableStringify(value))),
  );
  const recipientKey = await importRsaEncryptionPublicKey(publicKey);
  const encryptedKey = await crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    recipientKey,
    toArrayBuffer(aesKey),
  );

  return {
    algorithm: 'RSA-OAEP-SHA-256+A256GCM',
    encryptedKey: bytesToBase64(new Uint8Array(encryptedKey)),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

export async function decryptJsonWithPrivateKey<T = unknown>(
  envelope: RsaOaepEncryptedEnvelope,
  privateKey: string,
): Promise<T> {
  const recipientKey = await importRsaEncryptionPrivateKey(privateKey);
  const decryptedKey = await crypto.subtle.decrypt(
    {
      name: 'RSA-OAEP',
    },
    recipientKey,
    toArrayBuffer(base64ToBytes(envelope.encryptedKey)),
  );
  const contentKey = await crypto.subtle.importKey(
    'raw',
    decryptedKey,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(base64ToBytes(envelope.iv)),
    },
    contentKey,
    toArrayBuffer(base64ToBytes(envelope.ciphertext)),
  );

  return JSON.parse(new TextDecoder().decode(new Uint8Array(plaintext))) as T;
}
