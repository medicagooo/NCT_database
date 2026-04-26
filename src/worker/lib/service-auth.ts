import { hmacSha256, sha256 } from './crypto';

const SERVICE_AUTH_TOKEN_ALGORITHM = 'NCT-MOTHER-AUTH-HMAC-SHA256-T30-V1';
const SERVICE_AUTH_TOKEN_STEP_MS = 30 * 1000;

function getServiceAuthTokenWindow(nowMs = Date.now()): number {
  return Math.floor(nowMs / SERVICE_AUTH_TOKEN_STEP_MS);
}

function buildServiceAuthTokenMessage(
  serviceUrl: string,
  window: number,
): string {
  return [
    SERVICE_AUTH_TOKEN_ALGORITHM,
    serviceUrl.trim(),
    String(window),
  ].join('\n');
}

async function secureEquals(left: string, right: string): Promise<boolean> {
  const [leftDigest, rightDigest] = await Promise.all([
    sha256(`nct-service-auth:${left}`),
    sha256(`nct-service-auth:${right}`),
  ]);

  return leftDigest === rightDigest;
}

export function readBearerToken(request: Request): string | null {
  const authorization = request.headers.get('authorization');
  if (authorization?.startsWith('Bearer ')) {
    return authorization.slice('Bearer '.length).trim();
  }

  return request.headers.get('x-api-token')?.trim() || null;
}

export async function deriveServiceAuthToken(
  serviceUrl: string,
  nowMs = Date.now(),
): Promise<string> {
  const trimmedServiceUrl = serviceUrl.trim();
  return hmacSha256(
    buildServiceAuthTokenMessage(
      trimmedServiceUrl,
      getServiceAuthTokenWindow(nowMs),
    ),
    trimmedServiceUrl,
  );
}

export async function verifyServiceAuthToken(
  serviceUrl: string,
  token: string | null,
  nowMs = Date.now(),
): Promise<boolean> {
  const trimmedServiceUrl = serviceUrl.trim();
  const trimmedToken = token?.trim() || '';
  if (!trimmedServiceUrl || !trimmedToken) {
    return false;
  }

  const currentWindow = getServiceAuthTokenWindow(nowMs);
  for (const window of [
    currentWindow - 1,
    currentWindow,
    currentWindow + 1,
  ]) {
    const expectedToken = await hmacSha256(
      buildServiceAuthTokenMessage(trimmedServiceUrl, window),
      trimmedServiceUrl,
    );
    if (await secureEquals(expectedToken, trimmedToken)) {
      return true;
    }
  }

  return false;
}
