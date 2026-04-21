import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { apiRequest } from './api';

describe('apiRequest', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends JSON requests with bearer auth when provided', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          'content-type': 'application/json',
        },
      }),
    );

    const response = await apiRequest<{ ok: boolean }>('/api/admin/export-now', {
      method: 'POST',
      token: 'secret-token',
      body: { export: true },
    });

    expect(response).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledWith('/api/admin/export-now', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer secret-token',
      },
      body: JSON.stringify({ export: true }),
    });
  });

  it('returns null for 204 responses', async () => {
    fetchMock.mockResolvedValue(
      new Response(null, {
        status: 204,
      }),
    );

    const response = await apiRequest<null>('/api/health');

    expect(response).toBeNull();
  });

  it('throws the server response body for failed requests', async () => {
    fetchMock.mockResolvedValue(
      new Response('Export failed.', {
        status: 500,
      }),
    );

    await expect(
      apiRequest('/api/admin/export-now', {
        method: 'POST',
      }),
    ).rejects.toThrow('Export failed.');
  });
});
