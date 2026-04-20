"use client";

/**
 * AuthContext — global authentication state.
 *
 * On mount, attempts a silent token refresh using the HttpOnly refresh-token
 * cookie. If successful, the user is considered authenticated and the access
 * token is stored in memory only (never localStorage).
 *
 * All child components access auth state via useAuth().
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { useRouter } from "next/navigation";

import { clearAccessToken, setAccessToken } from "@/lib/auth";
import { api, apiSilentRefresh, ApiError } from "@/lib/api";
import type { MeResponse, User } from "@/types/auth";

// ── Context shape ─────────────────────────────────────────────────────────────

interface AuthContextValue {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, orgName: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// ── Provider ──────────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  // Silent refresh on app mount — re-hydrate in-memory token from HttpOnly cookie
  useEffect(() => {
    (async () => {
      try {
        const data = await apiSilentRefresh();
        if (data) {
          setAccessToken(data.access_token, data.expires_in);
          setUser(data.user);
        }
      } finally {
        setIsLoading(false);
      }
    })();
  }, []);

  const login = useCallback(
    async (email: string, password: string): Promise<void> => {
      const data = await api.post<MeResponse>("/auth/login", {
        email,
        password,
      });
      setAccessToken(data.access_token, data.expires_in);
      setUser(data.user);
      router.push("/dashboard");
    },
    [router],
  );

  const register = useCallback(
    async (
      email: string,
      password: string,
      orgName: string,
    ): Promise<void> => {
      const data = await api.post<MeResponse>("/auth/register", {
        email,
        password,
        org_name: orgName,
      });
      setAccessToken(data.access_token, data.expires_in);
      setUser(data.user);
      router.push("/dashboard");
    },
    [router],
  );

  const logout = useCallback(async (): Promise<void> => {
    try {
      await api.post("/auth/logout");
    } catch {
      // Swallow errors — we always clear local state
    } finally {
      clearAccessToken();
      setUser(null);
      router.push("/login");
    }
  }, [router]);

  const refreshUser = useCallback(async (): Promise<void> => {
    const data = await apiSilentRefresh();
    if (data) {
      setAccessToken(data.access_token, data.expires_in);
      setUser(data.user);
    }
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated: user !== null,
        login,
        register,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within <AuthProvider>");
  }
  return ctx;
}
