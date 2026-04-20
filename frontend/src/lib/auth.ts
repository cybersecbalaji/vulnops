/**
 * In-memory access token store.
 *
 * SECURITY REQUIREMENT (PRD §Auth Architecture):
 *   The JWT access token MUST be stored in memory only — never in
 *   localStorage or sessionStorage. This prevents XSS-based token theft.
 *
 * The refresh token lives in an HttpOnly, Secure, SameSite=Strict cookie
 * managed exclusively by the browser/backend — JavaScript cannot read it.
 *
 * On page refresh, the access token is lost (expected). The app calls
 * /auth/refresh on mount to silently re-issue it using the HttpOnly cookie.
 */

let _accessToken: string | null = null;
let _tokenExpiresAt: number | null = null; // Unix timestamp (ms)

export function setAccessToken(token: string, expiresInSeconds: number): void {
  _accessToken = token;
  _tokenExpiresAt = Date.now() + expiresInSeconds * 1000;
}

export function getAccessToken(): string | null {
  return _accessToken;
}

export function clearAccessToken(): void {
  _accessToken = null;
  _tokenExpiresAt = null;
}

/** Returns true if the stored token has expired (or is about to, within 30s). */
export function isTokenExpiredOrExpiring(): boolean {
  if (!_accessToken || !_tokenExpiresAt) return true;
  return Date.now() >= _tokenExpiresAt - 30_000;
}
