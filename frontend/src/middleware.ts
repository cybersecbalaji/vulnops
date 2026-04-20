/**
 * Next.js Edge Middleware — route protection.
 *
 * The refresh-token HttpOnly cookie cannot be read by JavaScript (by design),
 * but it IS visible to the middleware (runs server-side on the edge).
 * We use its presence as a session hint to decide whether to redirect.
 *
 * Security note: the middleware is a UX guard, not a security boundary.
 * Real auth enforcement happens on the backend via JWT validation.
 * A user with a stale/invalid refresh cookie will be redirected to login
 * by the client-side AuthContext on the first API call.
 */

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const REFRESH_COOKIE_NAME = "refresh_token";

// Routes that require authentication
const PROTECTED_PREFIXES = ["/dashboard", "/findings", "/assets", "/reports", "/settings", "/remediation"];

// Routes accessible only when NOT authenticated (prevent logged-in users seeing login)
const AUTH_ONLY_ROUTES = ["/login", "/register"];

export function middleware(request: NextRequest): NextResponse {
  const { pathname } = request.nextUrl;
  const hasRefreshCookie = request.cookies.has(REFRESH_COOKIE_NAME);

  // Redirect logged-in users away from auth pages
  if (AUTH_ONLY_ROUTES.some((r) => pathname.startsWith(r)) && hasRefreshCookie) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  // Redirect unauthenticated users to login for protected pages
  if (PROTECTED_PREFIXES.some((p) => pathname.startsWith(p)) && !hasRefreshCookie) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("next", pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  // Apply middleware to all routes except static assets and API proxy
  matcher: ["/((?!_next/static|_next/image|favicon.ico|api/).*)"],
};
