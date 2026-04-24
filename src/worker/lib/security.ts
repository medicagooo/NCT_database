import type { Context } from 'hono';
import { stableStringify } from './json';

const encoder = new TextEncoder();
const SERVICE_SIGNATURE_ALGORITHM = 'ECDSA-P256-SHA256';
const MOTHER_SERVICE_KEY_ID = 'mother-main';

type ServiceAuthEnv = {
  SERVICE_SIGNING_PRIVATE_KEY?: string;
};

type SignedPayloadEnvelope<T> = {
  payload: T;
  signature: {
    algorithm: typeof SERVICE_SIGNATURE_ALGORITHM;
    kid: typeof MOTHER_SERVICE_KEY_ID;
    signedAt: string;
    nonce: string;
    payloadHash: string;
    value: string;
  };
};

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

function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
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

function base64ToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const paddingLength = (4 - (normalized.length % 4)) % 4;
  const binary = atob(`${normalized}${'='.repeat(paddingLength)}`);
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

export function readToken(request: Request): string | null {
  const authorization = request.headers.get('authorization');
  if (authorization?.startsWith('Bearer ')) {
    return authorization.slice('Bearer '.length).trim();
  }

  return request.headers.get('x-api-token');
}

async function sha256Base64Url(input: string | ArrayBuffer): Promise<string> {
  const bytes = typeof input === 'string'
    ? encoder.encode(input)
    : new Uint8Array(input);
  const digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(bytes));
  return bytesToBase64Url(new Uint8Array(digest));
}

async function importSigningPrivateKey(
  value: string,
  extractable = false,
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'pkcs8',
    toArrayBuffer(base64ToBytes(readPemBody(value))),
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    extractable,
    ['sign'],
  );
}

function buildRequestCanonicalString(input: {
  bodyHash: string;
  method: string;
  nonce: string;
  pathWithSearch: string;
  timestamp: string;
}): string {
  return [
    'NCT-SERVICE-AUTH-V1',
    input.method.toUpperCase(),
    input.pathWithSearch,
    input.timestamp,
    input.nonce,
    input.bodyHash,
  ].join('\n');
}

function buildPayloadCanonicalString(input: {
  keyId: string;
  nonce: string;
  payloadHash: string;
  signedAt: string;
}): string {
  return [
    'NCT-PAYLOAD-SIGNATURE-V1',
    input.keyId,
    input.signedAt,
    input.nonce,
    input.payloadHash,
  ].join('\n');
}

function createUnauthorizedResponse(context: Context, message: string): Response {
  return context.json(
    {
      error: message,
    },
    401,
  );
}

export async function deriveSigningPublicKeyFromPrivateKey(
  privateKey: string,
): Promise<string> {
  const importedPrivateKey = await importSigningPrivateKey(privateKey, true);
  const exportedJwk = await crypto.subtle.exportKey(
    'jwk',
    importedPrivateKey,
  ) as JsonWebKey;

  if (
    exportedJwk.kty !== 'EC'
    || exportedJwk.crv !== 'P-256'
    || typeof exportedJwk.x !== 'string'
    || typeof exportedJwk.y !== 'string'
  ) {
    throw new Error('SERVICE_SIGNING_PRIVATE_KEY is not a valid ECDSA P-256 private key.');
  }

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    {
      crv: 'P-256',
      ext: true,
      key_ops: ['verify'],
      kty: 'EC',
      x: exportedJwk.x,
      y: exportedJwk.y,
    },
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['verify'],
  );
  const spki = await crypto.subtle.exportKey('spki', publicKey) as ArrayBuffer;

  return bytesToPem(new Uint8Array(spki), 'PUBLIC KEY');
}

export async function buildServiceAuthHeaders(
  env: ServiceAuthEnv,
  input: {
    body?: string;
    method: string;
    url: string;
  },
): Promise<Record<string, string>> {
  const privateKey = env.SERVICE_SIGNING_PRIVATE_KEY?.trim();
  if (!privateKey) {
    return {};
  }

  const timestamp = new Date().toISOString();
  const nonce = crypto.randomUUID();
  const bodyHash = await sha256Base64Url(input.body ?? '');
  const url = new URL(input.url);
  const canonical = buildRequestCanonicalString({
    bodyHash,
    method: input.method,
    nonce,
    pathWithSearch: `${url.pathname}${url.search}`,
    timestamp,
  });
  const key = await importSigningPrivateKey(privateKey);
  const signature = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: 'SHA-256',
    },
    key,
    toArrayBuffer(encoder.encode(canonical)),
  );

  return {
    'x-nct-auth-alg': SERVICE_SIGNATURE_ALGORITHM,
    'x-nct-key-id': MOTHER_SERVICE_KEY_ID,
    'x-nct-timestamp': timestamp,
    'x-nct-nonce': nonce,
    'x-nct-body-sha256': bodyHash,
    'x-nct-signature': bytesToBase64Url(new Uint8Array(signature)),
  };
}

export async function signPayloadEnvelope<T>(
  env: ServiceAuthEnv,
  payload: T,
): Promise<T | SignedPayloadEnvelope<T>> {
  const privateKey = env.SERVICE_SIGNING_PRIVATE_KEY?.trim();
  if (!privateKey) {
    return payload;
  }

  const signedAt = new Date().toISOString();
  const nonce = crypto.randomUUID();
  const payloadHash = await sha256Base64Url(stableStringify(payload));
  const canonical = buildPayloadCanonicalString({
    keyId: MOTHER_SERVICE_KEY_ID,
    nonce,
    payloadHash,
    signedAt,
  });
  const key = await importSigningPrivateKey(privateKey);
  const signature = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: 'SHA-256',
    },
    key,
    toArrayBuffer(encoder.encode(canonical)),
  );

  return {
    payload,
    signature: {
      algorithm: SERVICE_SIGNATURE_ALGORITHM,
      kid: MOTHER_SERVICE_KEY_ID,
      signedAt,
      nonce,
      payloadHash,
      value: bytesToBase64Url(new Uint8Array(signature)),
    },
  };
}

export function assertToken(
  context: Context,
  expectedToken: string | undefined,
  label: string,
): Response | null {
  if (!expectedToken) {
    return null;
  }

  const providedToken = readToken(context.req.raw);
  if (providedToken === expectedToken) {
    return null;
  }

  return createUnauthorizedResponse(context, `${label} token is invalid.`);
}
