"use client";

import { useState } from "react";
import Link from "next/link";
import { useAuth } from "@/contexts/AuthContext";
import { ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ShieldAlert, Eye, EyeOff, CheckCircle2, XCircle } from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";

function PasswordStrengthIndicator({ password }: { password: string }) {
  const checks = [
    { label: "At least 12 characters", ok: password.length >= 12 },
    { label: "Contains a number", ok: /\d/.test(password) },
    { label: "Contains a special character", ok: /[^a-zA-Z0-9]/.test(password) },
    { label: "Contains uppercase letter", ok: /[A-Z]/.test(password) },
  ];

  if (!password) return null;

  return (
    <ul className="mt-2 space-y-1">
      {checks.map(({ label, ok }) => (
        <li key={label} className="flex items-center gap-1.5 text-xs">
          {ok ? (
            <CheckCircle2 className="h-3.5 w-3.5 text-green-600 shrink-0" />
          ) : (
            <XCircle className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
          )}
          <span className={ok ? "text-green-700" : "text-muted-foreground"}>
            {label}
          </span>
        </li>
      ))}
    </ul>
  );
}

export function RegisterForm() {
  const { register } = useAuth();
  const [orgName, setOrgName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password.length < 12) {
      setError("Password must be at least 12 characters long.");
      return;
    }

    setIsLoading(true);
    try {
      await register(email, password, orgName);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-muted/30 px-4 py-12">
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>
      <div className="w-full max-w-md">
        {/* Brand header */}
        <div className="mb-8 flex items-center justify-center gap-2">
          <ShieldAlert className="h-8 w-8 text-primary" />
          <span className="text-2xl font-bold tracking-tight">VulnOps</span>
        </div>

        <Card>
          <CardHeader className="space-y-1">
            <CardTitle className="text-xl">Create your organization</CardTitle>
            <CardDescription>
              Set up VulnOps for your security team. You&apos;ll be the admin.
            </CardDescription>
          </CardHeader>

          <CardContent>
            <form onSubmit={handleSubmit} noValidate className="space-y-4">
              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <div className="space-y-2">
                <Label htmlFor="org_name">Organization name</Label>
                <Input
                  id="org_name"
                  type="text"
                  autoComplete="organization"
                  placeholder="Acme Security"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  required
                  minLength={2}
                  maxLength={100}
                  disabled={isLoading}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="email">Work email</Label>
                <Input
                  id="email"
                  type="email"
                  autoComplete="email"
                  placeholder="you@acme.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  disabled={isLoading}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    autoComplete="new-password"
                    placeholder="Minimum 12 characters"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    minLength={12}
                    maxLength={128}
                    disabled={isLoading}
                    className="pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((v) => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>
                <PasswordStrengthIndicator password={password} />
              </div>

              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading ? "Creating account…" : "Create account"}
              </Button>
            </form>
          </CardContent>

          <CardFooter className="justify-center">
            <p className="text-sm text-muted-foreground">
              Already have an account?{" "}
              <Link
                href="/login"
                className="font-medium text-primary hover:underline"
              >
                Sign in
              </Link>
            </p>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
