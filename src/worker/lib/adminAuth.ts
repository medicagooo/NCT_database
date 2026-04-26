import type { Context } from 'hono';
import { readBearerToken } from './service-auth';

const encoder = new TextEncoder();
// Cloudflare Workers rejects PBKDF2 iteration counts above 100,000.
const PASSWORD_ITERATIONS = 100_000;
const ADMIN_ID = 'admin';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

type AdminCredentialRow = {
  password_hash: string;
  salt: string;
  iterations: number;
};

type AdminSessionRow = {
  id: string;
  expires_at: string;
};

export class AdminAuthError extends Error {
  code: string;
  status: number;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'AdminAuthError';
    this.status = status;
    this.code = code;
  }
}

function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  return view.buffer.slice(
    view.byteOffset,
    view.byteOffset + view.byteLength,
  ) as ArrayBuffer;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const paddingLength = (4 - (normalized.length % 4)) % 4;
  const binary = atob(`${normalized}${'='.repeat(paddingLength)}`);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function randomBase64Url(byteLength: number): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    toArrayBuffer(encoder.encode(value)),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

async function derivePasswordHash(
  password: string,
  salt: string,
  iterations: number,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(encoder.encode(password)),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: toArrayBuffer(base64UrlToBytes(salt)),
      iterations,
    },
    key,
    256,
  );

  return bytesToBase64Url(new Uint8Array(bits));
}

async function secureEquals(left: string, right: string): Promise<boolean> {
  const leftDigest = await sha256Base64Url(`left:${left}`);
  const rightDigest = await sha256Base64Url(`left:${right}`);
  return leftDigest === rightDigest;
}

function normalizePassword(password: unknown): string {
  return typeof password === 'string' ? password : '';
}

function assertAcceptablePassword(password: string) {
  if (password.length < 12) {
    throw new AdminAuthError(
      400,
      'admin_password_too_short',
      'Admin password must be at least 12 characters.',
    );
  }
}

async function readCredential(db: D1Database): Promise<AdminCredentialRow | null> {
  const row = await db
    .prepare(
      `
        SELECT password_hash, salt, iterations
        FROM admin_credentials
        WHERE id = ?
      `,
    )
    .bind(ADMIN_ID)
    .first<AdminCredentialRow>();

  return row ?? null;
}

async function createSession(db: D1Database): Promise<{
  expiresAt: string;
  sessionToken: string;
}> {
  const sessionToken = randomBase64Url(32);
  const tokenHash = await sha256Base64Url(sessionToken);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_MS).toISOString();

  await db
    .prepare(
      `
        DELETE FROM admin_sessions
        WHERE expires_at <= ?
      `,
    )
    .bind(now.toISOString())
    .run();

  await db
    .prepare(
      `
        INSERT INTO admin_sessions (
          id,
          token_hash,
          created_at,
          expires_at
        )
        VALUES (?, ?, ?, ?)
      `,
    )
    .bind(crypto.randomUUID(), tokenHash, now.toISOString(), expiresAt)
    .run();

  return {
    expiresAt,
    sessionToken,
  };
}

export async function getAdminAuthStatus(db: D1Database): Promise<{
  configured: boolean;
}> {
  return {
    configured: Boolean(await readCredential(db)),
  };
}

export async function setupAdminPassword(
  db: D1Database,
  passwordInput: unknown,
): Promise<{
  expiresAt: string;
  sessionToken: string;
}> {
  if (await readCredential(db)) {
    throw new AdminAuthError(
      409,
      'admin_password_already_configured',
      'Admin password is already configured.',
    );
  }

  const password = normalizePassword(passwordInput);
  assertAcceptablePassword(password);

  const now = new Date().toISOString();
  const salt = randomBase64Url(16);
  const passwordHash = await derivePasswordHash(
    password,
    salt,
    PASSWORD_ITERATIONS,
  );

  try {
    await db
      .prepare(
        `
          INSERT INTO admin_credentials (
            id,
            password_hash,
            salt,
            iterations,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?)
        `,
      )
      .bind(
        ADMIN_ID,
        passwordHash,
        salt,
        PASSWORD_ITERATIONS,
        now,
        now,
      )
      .run();
  } catch (_error) {
    throw new AdminAuthError(
      409,
      'admin_password_already_configured',
      'Admin password is already configured.',
    );
  }

  return createSession(db);
}

export async function loginAdminPassword(
  db: D1Database,
  passwordInput: unknown,
): Promise<{
  expiresAt: string;
  sessionToken: string;
}> {
  const credential = await readCredential(db);
  if (!credential) {
    throw new AdminAuthError(
      409,
      'admin_setup_required',
      'Admin password is not configured.',
    );
  }

  const password = normalizePassword(passwordInput);
  const passwordHash = await derivePasswordHash(
    password,
    credential.salt,
    Number(credential.iterations),
  );

  if (!(await secureEquals(passwordHash, credential.password_hash))) {
    throw new AdminAuthError(
      401,
      'admin_login_failed',
      'Admin password is invalid.',
    );
  }

  return createSession(db);
}

export async function deleteAdminSession(
  db: D1Database,
  request: Request,
): Promise<void> {
  const token = readBearerToken(request);
  if (!token) {
    return;
  }

  await db
    .prepare(
      `
        DELETE FROM admin_sessions
        WHERE token_hash = ?
      `,
    )
    .bind(await sha256Base64Url(token))
    .run();
}

async function verifyAdminSession(
  db: D1Database,
  request: Request,
): Promise<boolean> {
  const token = readBearerToken(request);
  if (!token) {
    return false;
  }

  const tokenHash = await sha256Base64Url(token);
  const row = await db
    .prepare(
      `
        SELECT id, expires_at
        FROM admin_sessions
        WHERE token_hash = ?
      `,
    )
    .bind(tokenHash)
    .first<AdminSessionRow>();

  if (!row) {
    return false;
  }

  const now = Date.now();
  const expiresAt = Date.parse(row.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) {
    await db
      .prepare(
        `
          DELETE FROM admin_sessions
          WHERE id = ?
        `,
      )
      .bind(row.id)
      .run();
    return false;
  }

  return true;
}

export async function assertAdminAuth(
  context: Context<{ Bindings: Env }>,
): Promise<Response | null> {
  const credential = await readCredential(context.env.DB);
  if (!credential) {
    return context.json(
      {
        code: 'admin_setup_required',
        error: 'Admin password is not configured.',
      },
      401,
    );
  }

  if (await verifyAdminSession(context.env.DB, context.req.raw)) {
    return null;
  }

  return context.json(
    {
      code: 'admin_login_required',
      error: 'Admin login is required.',
    },
    401,
  );
}
