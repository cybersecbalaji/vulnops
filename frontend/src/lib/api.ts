/**
 * Typed API client for VulnOps backend.
 *
 * Token refresh strategy:
 *   1. Every request checks if the in-memory access token is present.
 *   2. If missing or within 30s of expiry, silently call /auth/refresh first
 *      (the HttpOnly cookie is sent automatically by the browser).
 *   3. If the refresh also fails (e.g., cookie expired), the caller receives
 *      an ApiError and the AuthContext clears local state → redirect to login.
 */

import {
  clearAccessToken,
  getAccessToken,
  isTokenExpiredOrExpiring,
  setAccessToken,
} from "./auth";
import type { MeResponse, TokenResponse } from "@/types/auth";

const API_BASE = "/api/v1";

// ── Token refresh ─────────────────────────────────────────────────────────────

let _refreshPromise: Promise<string | null> | null = null;

async function _refreshAccessToken(): Promise<string | null> {
  // Deduplicate concurrent refresh calls
  if (_refreshPromise) return _refreshPromise;

  _refreshPromise = fetch(`${API_BASE}/auth/refresh`, {
    method: "POST",
    credentials: "include", // sends HttpOnly refresh-token cookie
  })
    .then(async (res) => {
      if (!res.ok) {
        clearAccessToken();
        return null;
      }
      const data: TokenResponse = await res.json();
      setAccessToken(data.access_token, data.expires_in);
      return data.access_token;
    })
    .catch(() => {
      clearAccessToken();
      return null;
    })
    .finally(() => {
      _refreshPromise = null;
    });

  return _refreshPromise;
}

// ── Core request helper ───────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function _getValidToken(): Promise<string | null> {
  if (isTokenExpiredOrExpiring()) {
    return _refreshAccessToken();
  }
  return getAccessToken();
}

export async function apiRequest<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = await _getValidToken();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: "include", // always include cookies for refresh
    headers,
  });

  if (response.status === 204) {
    return undefined as unknown as T;
  }

  const data = await response.json().catch(() => ({
    detail: "Unexpected response from server.",
  }));

  if (!response.ok) {
    const message =
      typeof data.detail === "string"
        ? data.detail
        : Array.isArray(data.detail)
          ? data.detail.map((e: { message: string }) => e.message).join("; ")
          : "An error occurred.";
    throw new ApiError(response.status, message);
  }

  return data as T;
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

export async function apiSilentRefresh(): Promise<MeResponse | null> {
  try {
    const data = await fetch(`${API_BASE}/auth/me`, {
      method: "GET",
      credentials: "include",
      headers: getAccessToken()
        ? { Authorization: `Bearer ${getAccessToken()}` }
        : {},
    });

    if (!data.ok) {
      // Try refresh
      const token = await _refreshAccessToken();
      if (!token) return null;

      const retryResp = await fetch(`${API_BASE}/auth/me`, {
        method: "GET",
        credentials: "include",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!retryResp.ok) return null;
      return retryResp.json();
    }
    return data.json();
  } catch {
    return null;
  }
}

export const api = {
  get: <T>(path: string) => apiRequest<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    apiRequest<T>(path, {
      method: "POST",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  patch: <T>(path: string, body: unknown) =>
    apiRequest<T>(path, { method: "PATCH", body: JSON.stringify(body) }),
  delete: <T>(path: string) => apiRequest<T>(path, { method: "DELETE" }),
};
