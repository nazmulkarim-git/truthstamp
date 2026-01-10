import { authHeaders, clearToken } from "./auth";

export const API_URL = process.env.NEXT_PUBLIC_API_URL || "/api";

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const url = path.startsWith("http") ? path : `${API}${path}`;
  const headers: HeadersInit = {
    ...(init?.headers || {}),
    ...authHeaders(),
  };
  const res = await fetch(url, { ...init, headers });
  if (res.status === 401) {
    // token expired or not approved
    clearToken();
  }
  return res;
}

export async function apiJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(path, init);
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(txt || `Request failed: ${res.status}`);
  }
  return (await res.json()) as T;
}
