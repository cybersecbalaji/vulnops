import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { AuthProvider } from "@/contexts/AuthContext";
import { ThemeProvider } from "@/contexts/ThemeContext";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "VulnOps Triage Console",
  description: "AI-powered vulnerability triage platform for security teams",
  robots: "noindex, nofollow", // Security tool — never index
};

// Pre-hydration script: sets the `.dark` class on <html> before React mounts
// so the first paint matches the user's saved / system preference. This
// prevents the "flash of incorrect theme" that happens when the toggle is
// applied in a client-side effect.
const themeInitScript = `
(function() {
  try {
    var s = localStorage.getItem('vulnops-theme') || 'system';
    var t = s === 'system'
      ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
      : s;
    if (t === 'dark') document.documentElement.classList.add('dark');
  } catch (_) {}
})();
`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body className={inter.className}>
        <ThemeProvider>
          <AuthProvider>{children}</AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
