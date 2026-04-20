export type Role = "admin" | "analyst" | "readonly";

export interface User {
  id: string;
  email: string;
  role: Role;
  org_id: string;
  created_at: string;
  last_login: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface MeResponse extends TokenResponse {
  user: User;
}

export interface SessionInfo {
  id: string;
  created_at: string;
  expires_at: string;
  user_agent: string | null;
  ip_address: string | null;
  is_current: boolean;
}

export interface ApiError {
  detail: string | { field: string; message: string }[];
}
