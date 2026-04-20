/** @type {import('next').NextConfig} */
const nextConfig = {
  // Strict mode catches common React bugs in development
  reactStrictMode: true,

  // Security headers applied at the Next.js layer (the backend also sets them
  // but defense in depth means both layers enforce them)
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "X-Frame-Options",
            value: "DENY",
          },
          {
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            key: "Referrer-Policy",
            value: "strict-origin-when-cross-origin",
          },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=()",
          },
          {
            key: "Strict-Transport-Security",
            value: "max-age=31536000; includeSubDomains; preload",
          },
        ],
      },
    ];
  },

  // Rewrite /api/* → backend in development (avoids CORS in dev)
  async rewrites() {
    return process.env.NODE_ENV === "development"
      ? [
          {
            source: "/api/v1/:path*",
            destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/v1/:path*`,
          },
        ]
      : [];
  },
};

module.exports = nextConfig;
