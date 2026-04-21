/** @type {import('next').NextConfig} */
const nextConfig = {
  // API proxy is handled by src/app/api/v1/[...path]/route.ts (Route Handler).
  // Using a Route Handler instead of rewrites ensures trailing slashes and
  // exact paths are preserved, preventing 308 redirects from leaking the
  // internal Railway backend URL to the browser.
};

module.exports = nextConfig;
