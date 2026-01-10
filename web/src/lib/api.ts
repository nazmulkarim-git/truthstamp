import { authHeaders } from "./auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "https://truthstamp-api.onrender.com";

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const url = path.startsWith("http") ? path : `${API_BASE}${path}`;

  const headers: HeadersInit = {
    ...(init?.headers || {}),
    ...authHeaders(),
  };

  return fetch(url, {
    ...init,
    headers,
  });
}

export async function apiJson<T = any>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(path, init);
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(t || res.statusText);
  }
  return res.json();
}