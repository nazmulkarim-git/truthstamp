"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:10000";

type PendingUser = {
  id: string;
  name?: string | null;
  email: string;
  phone?: string | null;
  occupation?: string | null;
  company?: string | null;
  extras?: any;
  created_at?: string;
};

type Overview = {
  counts: Record<string, number>;
  recent_events: any[];
};

async function apiFetch(path: string, adminKey: string, init?: RequestInit) {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      ...(init?.headers || {}),
      "X-Admin-Key": adminKey,
    },
    cache: "no-store",
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`${res.status} ${t}`);
  }
  return res;
}

export default function AdminClient() {
  const [adminKey, setAdminKey] = useState("");
  const [savedKey, setSavedKey] = useState<string | null>(null);

  const [overview, setOverview] = useState<Overview | null>(null);
  const [pending, setPending] = useState<PendingUser[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [cases, setCases] = useState<any[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const k = typeof window !== "undefined" ? window.localStorage.getItem("truthstamp_admin_key") : null;
    if (k) {
      setSavedKey(k);
      setAdminKey(k);
    }
  }, []);

  const keyReady = useMemo(() => (adminKey || "").trim().length > 0, [adminKey]);

  async function refreshAll(key: string) {
    setBusy(true);
    setErr(null);
    try {
      const o = await apiFetch("/admin/overview", key);
      setOverview(await o.json());

      const p = await apiFetch("/admin/pending-users", key);
      const pj = await p.json();
      setPending(pj?.pending || []);

      const u = await apiFetch("/admin/users?status=all", key);
      const uj = await u.json();
      setUsers(uj?.users || []);

      const c = await apiFetch("/admin/cases", key);
      const cj = await c.json();
      setCases(cj?.cases || []);
    } catch (e: any) {
      setErr(e?.message || "Failed");
    } finally {
      setBusy(false);
    }
  }

  async function approve(userId: string) {
    if (!adminKey) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await apiFetch(`/admin/approve-user/${userId}`, adminKey, { method: "POST" });
      const j = await r.json();
      const pw = j?.temp_password;
      alert(`Approved. Temporary password:\n\n${pw}\n\n(If SMTP is configured, it was emailed. Otherwise copy + send manually.)`);
      await refreshAll(adminKey);
    } catch (e: any) {
      setErr(e?.message || "Approve failed");
    } finally {
      setBusy(false);
    }
  }

  async function disableUser(userId: string) {
    if (!adminKey) return;
    setBusy(true);
    setErr(null);
    try {
      await apiFetch(`/admin/users/${userId}/disable`, adminKey, { method: "POST" });
      await refreshAll(adminKey);
    } catch (e: any) {
      setErr(e?.message || "Disable failed");
    } finally {
      setBusy(false);
    }
  }

  async function enableUser(userId: string) {
    if (!adminKey) return;
    setBusy(true);
    setErr(null);
    try {
      await apiFetch(`/admin/users/${userId}/enable`, adminKey, { method: "POST" });
      await refreshAll(adminKey);
    } catch (e: any) {
      setErr(e?.message || "Enable failed");
    } finally {
      setBusy(false);
    }
  }

  function saveKey() {
    const k = adminKey.trim();
    if (!k) return;
    window.localStorage.setItem("truthstamp_admin_key", k);
    setSavedKey(k);
    refreshAll(k);
  }

  function clearKey() {
    window.localStorage.removeItem("truthstamp_admin_key");
    setSavedKey(null);
    setAdminKey("");
    setOverview(null);
    setPending([]);
    setUsers([]);
    setCases([]);
  }

  return (
    <div className="min-h-screen bg-white">
      <div className="mx-auto max-w-6xl px-6 py-10">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-blue-700">TruthStamp Admin</p>
            <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Control Center</h1>
            <p className="mt-1 text-sm text-slate-600">
              Approve users, view cases, and monitor chain-of-custody events in one place.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost">
              <Link href="/">Home</Link>
            </Button>
            <Button variant="ghost" onClick={() => refreshAll(adminKey)} disabled={!keyReady || busy}>
              Refresh
            </Button>
          </div>
        </div>

        <Separator className="my-6" />

        <Card className="p-5">
          <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
            <div className="flex-1">
              <h2 className="font-medium text-slate-900">Admin Key</h2>
              <p className="text-sm text-slate-600">
                Paste your <span className="font-mono">TRUTHSTAMP_ADMIN_API_KEY</span> from Render → truthstamp-api → Environment.
              </p>
              <div className="mt-3 flex flex-col gap-2 sm:flex-row">
                <Input
                  placeholder="TRUTHSTAMP_ADMIN_API_KEY"
                  value={adminKey}
                  onChange={(e) => setAdminKey(e.target.value)}
                />
                <Button onClick={saveKey} disabled={!keyReady || busy} className="bg-blue-600 hover:bg-blue-700">
                  Save & Load
                </Button>
                <Button variant="ghost" onClick={clearKey} disabled={busy}>
                  Clear
                </Button>
              </div>
              {savedKey ? <p className="mt-2 text-xs text-slate-500">Key saved in this browser.</p> : null}
            </div>

            <div className="text-sm text-slate-600">
              {busy ? <span className="animate-pulse">Working…</span> : <span>Ready</span>}
            </div>
          </div>

          {err ? (
            <div className="mt-4 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
              {err}
            </div>
          ) : null}
        </Card>

        <div className="mt-8 grid gap-6 md:grid-cols-3">
          <Card className="p-5">
            <h3 className="text-sm font-medium text-slate-900">Users</h3>
            <p className="mt-2 text-3xl font-semibold text-slate-900">
              {overview?.counts?.users_total ?? "—"}
            </p>
            <p className="mt-1 text-xs text-slate-600">
              Pending: {overview?.counts?.users_pending ?? "—"} • Approved: {overview?.counts?.users_approved ?? "—"}
            </p>
          </Card>
          <Card className="p-5">
            <h3 className="text-sm font-medium text-slate-900">Cases</h3>
            <p className="mt-2 text-3xl font-semibold text-slate-900">
              {overview?.counts?.cases_total ?? "—"}
            </p>
            <p className="mt-1 text-xs text-slate-600">Total cases in database</p>
          </Card>
          <Card className="p-5">
            <h3 className="text-sm font-medium text-slate-900">Evidence</h3>
            <p className="mt-2 text-3xl font-semibold text-slate-900">
              {overview?.counts?.evidence_total ?? "—"}
            </p>
            <p className="mt-1 text-xs text-slate-600">Uploaded items across all cases</p>
          </Card>
        </div>

        <div className="mt-8 grid gap-6 lg:grid-cols-2">
          <Card className="p-5">
            <div className="flex items-center justify-between">
              <h2 className="font-medium text-slate-900">Pending Access Requests</h2>
              <span className="text-xs text-slate-500">{pending.length} pending</span>
            </div>
            <div className="mt-4 space-y-3">
              {!keyReady ? (
                <p className="text-sm text-slate-600">Enter your admin key to load requests.</p>
              ) : pending.length === 0 ? (
                <p className="text-sm text-slate-600">No pending requests.</p>
              ) : (
                pending.map((u) => (
                  <div key={u.id} className="rounded-lg border border-slate-200 p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <p className="font-medium text-slate-900">{u.name || "—"}</p>
                        <p className="text-sm text-slate-700">{u.email}</p>
                        <p className="mt-1 text-xs text-slate-600">
                          {u.company || "—"} • {u.occupation || "—"} • {u.phone || "—"}
                        </p>
                        <p className="mt-2 text-xs text-slate-500">
                          Use case: {(u.extras?.use_case || "—").toString()}
                        </p>
                      </div>
                      <Button
                        onClick={() => approve(u.id)}
                        disabled={busy}
                        className="bg-blue-600 hover:bg-blue-700"
                      >
                        Approve
                      </Button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </Card>

          <Card className="p-5">
            <div className="flex items-center justify-between">
              <h2 className="font-medium text-slate-900">System Snapshot</h2>
              <span className="text-xs text-slate-500">{users.length} users • {cases.length} cases</span>
            </div>

            <div className="mt-4">
              <h3 className="text-sm font-medium text-slate-900">Recent Users</h3>
              <div className="mt-2 space-y-2">
                {users.slice(0, 6).map((u) => (
                  <div key={u.id} className="flex items-center justify-between rounded-md border border-slate-200 px-3 py-2">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-slate-900">{u.name || "—"}</p>
                      <p className="truncate text-xs text-slate-600">{u.email}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      {u.is_active ? (
                        <Button variant="ghost" onClick={() => disableUser(u.id)} disabled={busy}>
                          Disable
                        </Button>
                      ) : (
                        <Button variant="ghost" onClick={() => enableUser(u.id)} disabled={busy}>
                          Enable
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              <Separator className="my-5" />

              <h3 className="text-sm font-medium text-slate-900">Recent Cases</h3>
              <div className="mt-2 space-y-2">
                {cases.slice(0, 6).map((c) => (
                  <div key={c.id} className="rounded-md border border-slate-200 px-3 py-2">
                    <p className="text-sm font-medium text-slate-900">{c.title}</p>
                    <p className="text-xs text-slate-600">{c.description || "—"}</p>
                  </div>
                ))}
              </div>
            </div>
          </Card>
        </div>

        <div className="mt-10 text-xs text-slate-500">
          Tip: Keep this admin page private. Anyone with the admin key can approve users and view everything.
        </div>
      </div>
    </div>
  );
}
