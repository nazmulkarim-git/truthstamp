// TruthStamp/web/src/lib/api.ts
import { authHeaders } from "./auth";

export const API =
  process.env.NEXT_PUBLIC_API_BASE || "https://truthstamp-api.onrender.com";

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const url = path.startsWith("http") ? path : `${API}${path}`;
  const headers: HeadersInit = {
    ...(init?.headers || {}),
    ...authHeaders(),
  };
  return fetch(url, { ...init, headers });
}

export async function apiJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(path, init);
  const ct = res.headers.get("content-type") || "";
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  if (ct.includes("application/json")) return (await res.json()) as T;
  return (await res.text()) as unknown as T;
}