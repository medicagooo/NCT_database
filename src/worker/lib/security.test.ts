import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import {
  assertToken,
  buildServiceAuthHeaders,
  deriveSigningPublicKeyFromPrivateKey,
} from './security';

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function toPem(buffer: ArrayBuffer, label: string) {
  const base64 = bytesToBase64(new Uint8Array(buffer));
  const chunks = base64.match(/.{1,64}/g) ?? [];
  return [
    `-----BEGIN ${label}-----`,
    ...chunks,
    `-----END ${label}-----`,
  ].join('\n');
}

async function generateSigningKeyPair(): Promise<{
  privateKey: string;
  publicKey: string;
}> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify'],
  );
  const [privateKey, publicKey] = await Promise.all([
    crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
    crypto.subtle.exportKey('spki', keyPair.publicKey),
  ]);

  return {
    privateKey: toPem(privateKey, 'PRIVATE KEY'),
    publicKey: toPem(publicKey, 'PUBLIC KEY'),
  };
}

function createApp(expectedToken?: string) {
  const app = new Hono();

  app.get('/', (context) => {
    const authError = assertToken(
      context,
      expectedToken,
      'Admin',
    );
    if (authError) {
      return authError;
    }

    return context.json({
      ok: true,
    });
  });

  return app;
}

describe('assertToken', () => {
  it('allows requests when the route does not require a token', async () => {
    const response = await createApp().request('/');

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true });
  });

  it('accepts bearer tokens from the authorization header', async () => {
    const response = await createApp('secret').request('/', {
      headers: {
        authorization: 'Bearer secret',
      },
    });

    expect(response.status).toBe(200);
  });

  it('accepts tokens from the x-api-token header', async () => {
    const response = await createApp('secret').request('/', {
      headers: {
        'x-api-token': 'secret',
      },
    });

    expect(response.status).toBe(200);
  });

  it('rejects invalid tokens with a 401 response', async () => {
    const response = await createApp('secret').request('/', {
      headers: {
        authorization: 'Bearer wrong',
      },
    });

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: 'Admin token is invalid.',
    });
  });
});

describe('buildServiceAuthHeaders', () => {
  it('builds ECDSA signed headers when the mother signing key is configured', async () => {
    const { privateKey } = await generateSigningKeyPair();

    const headers = await buildServiceAuthHeaders(
      {
        SERVICE_SIGNING_PRIVATE_KEY: privateKey,
      },
      {
        body: JSON.stringify({ hello: 'sub' }),
        method: 'GET',
        url: 'https://sub.example.com/api/export/nct_databack?afterVersion=1',
      },
    );

    expect(headers).toMatchObject({
      'x-nct-auth-alg': 'ECDSA-P256-SHA256',
      'x-nct-key-id': 'mother-main',
    });
    expect(headers['x-nct-signature']).toBeTruthy();
    expect(headers['x-nct-body-sha256']).toBeTruthy();
    expect(headers['x-nct-timestamp']).toBeTruthy();
    expect(headers['x-nct-nonce']).toBeTruthy();
  });
});

describe('deriveSigningPublicKeyFromPrivateKey', () => {
  it('derives the matching public key from the mother signing private key', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair();

    await expect(deriveSigningPublicKeyFromPrivateKey(privateKey))
      .resolves.toBe(publicKey);
  });
});
