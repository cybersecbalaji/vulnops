/**
 * Catch-all Route Handler that proxies /api/v1/** to the backend.
 *
 * Why a Route Handler instead of next.config.js rewrites:
 *   - Rewrites can strip trailing slashes before forwarding, causing FastAPI
 *     to 308-redirect to its own internal Railway URL (unreachable by browser).
 *   - Route Handlers receive the full pathname including trailing slashes.
 *   - We can follow redirects server-side, avoiding internal-URL exposure.
 */
import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.BACKEND_URL;

async function proxy(request: NextRequest): Promise<NextResponse> {
  if (!BACKEND_URL) {
    return NextResponse.json(
      { detail: "Backend not configured (BACKEND_URL missing)" },
      { status: 502 }
    );
  }

  // Reconstruct the backend URL preserving the full path + query string.
  const { pathname, search } = request.nextUrl;
  const backendUrl = `${BACKEND_URL}${pathname}${search}`;

  // Forward all request headers except Host (the backend sets its own).
  const forwardHeaders = new Headers(request.headers);
  forwardHeaders.delete("host");

  let body: BodyInit | null = null;
  if (request.method !== "GET" && request.method !== "HEAD") {
    body = await request.arrayBuffer();
  }

  let backendResp: Response;
  try {
    backendResp = await fetch(backendUrl, {
      method: request.method,
      headers: forwardHeaders,
      body: body ?? undefined,
      // Follow redirects server-side so the browser never sees internal URLs.
      redirect: "follow",
    });
  } catch (err) {
    console.error("[proxy] Backend fetch error:", err);
    return NextResponse.json(
      { detail: "Backend unreachable" },
      { status: 502 }
    );
  }

  // Copy response headers, skipping ones Next.js manages automatically.
  const respHeaders = new Headers();
  const skipHeaders = new Set([
    "transfer-encoding",
    "connection",
    "keep-alive",
    "content-encoding", // Next.js handles compression
  ]);
  backendResp.headers.forEach((value, key) => {
    if (!skipHeaders.has(key.toLowerCase())) {
      respHeaders.append(key, value);
    }
  });

  const responseBody =
    backendResp.status === 204 ? null : backendResp.body;

  return new NextResponse(responseBody, {
    status: backendResp.status,
    headers: respHeaders,
  });
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
export const HEAD = proxy;
export const OPTIONS = proxy;
