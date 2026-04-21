import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { assertToken } from './security';

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
