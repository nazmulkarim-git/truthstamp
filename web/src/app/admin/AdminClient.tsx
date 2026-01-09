"use client";

<<<<<<< HEAD
import * as React from "react";
import Link from "next/link";

type UserRow = {
  id?: string;
  name?: string;
=======
import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";

type UserRow = {
  id?: string | null;
  name?: string | null;
>>>>>>> 30d16ff (Temp pass)
  email: string;
  phone?: string | null;
  occupation?: string | null;
  company?: string | null;
<<<<<<< HEAD
  is_active?: boolean;
  is_approved?: boolean;
  must_change_password?: boolean;
  requested_at?: string;
  approved_at?: string | null;
};

type CaseRow = {
  id: string;
  title: string;
  description?: string | null;
  status?: string | null;
  created_at?: string;
};

type Overview = {
  counts?: {
    users_total?: number;
    users_pending?: number;
    users_approved?: number;
    cases_total?: number;
    evidence_total?: number;
    events_total?: number;
  };
  recent_users?: UserRow[];
  recent_cases?: CaseRow[];
  recent_events?: any[];
};

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/+$/, "") || "http://localhost:8000";

function cn(...xs: Array<string | false | undefined | null>) {
  return xs.filter(Boolean).join(" ");
}

async function api<T>(
  path: string,
  adminKey: string,
  init?: RequestInit
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      ...(init?.headers || {}),
=======
  must_change_password?: boolean;
  is_active?: boolean;
  is_approved?: boolean;
  requested_at?: string | null;
  approved_at?: string | null;
};

const API_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ||
  "http://localhost:8000";

function fmt(ts?: string | null) {
  if (!ts) return "";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

async function api<T>(
  path: string,
  adminKey: string,
  opts?: RequestInit
): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...opts,
    headers: {
      ...(opts?.headers || {}),
      "Content-Type": "application/json",
>>>>>>> 30d16ff (Temp pass)
      "x-admin-key": adminKey,
    },
    cache: "no-store",
  });

  if (!res.ok) {
<<<<<<< HEAD
    let msg = `${res.status} ${res.statusText}`;
    try {
      const j = await res.json();
      msg = j?.detail ? `${msg} — ${j.detail}` : `${msg} — ${JSON.stringify(j)}`;
    } catch {
      try {
        msg = `${msg} — ${await res.text()}`;
      } catch {}
    }
    throw new Error(msg);
=======
    const t = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}${t ? ` — ${t}` : ""}`);
>>>>>>> 30d16ff (Temp pass)
  }
  return (await res.json()) as T;
}

export default function AdminClient() {
<<<<<<< HEAD
  const [adminKey, setAdminKey] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [statusMsg, setStatusMsg] = React.useState<string>("");

  const [overview, setOverview] = React.useState<Overview | null>(null);
  const [pending, setPending] = React.useState<UserRow[]>([]);
  const [users, setUsers] = React.useState<UserRow[]>([]);
  const [cases, setCases] = React.useState<CaseRow[]>([]);

  React.useEffect(() => {
    const k = localStorage.getItem("truthstamp_admin_key") || "";
    if (k) setAdminKey(k);
  }, []);

  async function refreshAll(k?: string) {
    const key = (k ?? adminKey).trim();
    if (!key) {
      setStatusMsg("Paste your admin key first.");
      return;
    }
    setLoading(true);
    setStatusMsg("");
    try {
      const [o, p, u, c] = await Promise.all([
        api<Overview>("/admin/overview", key),
        api<UserRow[]>("/admin/pending-users", key),
        api<UserRow[]>("/admin/users?status=all", key),
        api<CaseRow[]>("/admin/cases", key),
      ]);

      setOverview(o);
      setPending(Array.isArray(p) ? p : []);
      setUsers(Array.isArray(u) ? u : []);
      setCases(Array.isArray(c) ? c : []);
      setStatusMsg("Loaded.");
    } catch (e: any) {
      setStatusMsg(e?.message || "Failed to load.");
=======
  const [adminKey, setAdminKey] = useState("");
  const [savedKey, setSavedKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<UserRow[]>([]);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const k = localStorage.getItem("truthstamp_admin_key") || "";
    setSavedKey(k);
    setAdminKey(k);
  }, []);

  const keyToUse = useMemo(() => (adminKey || savedKey).trim(), [adminKey, savedKey]);

  async function refreshAll() {
    if (!keyToUse) {
      setError("Enter your Admin Key first.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [p, u] = await Promise.all([
        api<UserRow[]>("/admin/pending-users", keyToUse),
        api<UserRow[]>("/admin/users?status=all", keyToUse),
      ]);
      setPending(p);
      setUsers(u);
    } catch (e: any) {
      setError(e?.message || "Failed to fetch");
>>>>>>> 30d16ff (Temp pass)
    } finally {
      setLoading(false);
    }
  }

  function saveKey() {
    localStorage.setItem("truthstamp_admin_key", adminKey.trim());
<<<<<<< HEAD
    refreshAll(adminKey.trim());
  }

  function clearKey() {
    localStorage.removeItem("truthstamp_admin_key");
    setAdminKey("");
    setStatusMsg("Cleared.");
=======
    setSavedKey(adminKey.trim());
  }

  async function approveAndIssueTemp(email: string) {
    if (!keyToUse) return;
    setLoading(true);
    setError(null);
    try {
      const out = await api<{ user: UserRow; temp_password?: string | null }>(
        "/admin/users/enable-by-email",
        keyToUse,
        {
          method: "POST",
          body: JSON.stringify({
            email,
            is_active: true,
            is_approved: true,
            issue_temp_password: true,
          }),
        }
      );

      if (out?.temp_password) {
        alert(
          `Temporary password for ${email}:\n\n${out.temp_password}\n\n(If SMTP is configured, it was emailed and won't be shown here.)`
        );
      } else {
        alert(`Approved ${email}. (If SMTP is configured, a temp password was emailed.)`);
      }

      await refreshAll();
    } catch (e: any) {
      setError(e?.message || "Approve failed");
    } finally {
      setLoading(false);
    }
  }

  async function setActive(email: string, active: boolean) {
    if (!keyToUse) return;
    setLoading(true);
    setError(null);
    try {
      await api("/admin/users/enable-by-email", keyToUse, {
        method: "POST",
        body: JSON.stringify({
          email,
          is_active: active,
          is_approved: null,
          issue_temp_password: false,
        }),
      });
      await refreshAll();
    } catch (e: any) {
      setError(e?.message || "Update failed");
    } finally {
      setLoading(false);
    }
>>>>>>> 30d16ff (Temp pass)
  }

  async function setUserFlags(
    email: string,
    next: { is_active: boolean; is_approved: boolean }
  ) {
    const key = adminKey.trim();
    if (!key) return;

    setLoading(true);
    setStatusMsg("");
    try {
      await api<{ ok: boolean }>(
        "/admin/users/enable-by-email",
        key,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, ...next }),
        }
      );
      await refreshAll(key);
    } catch (e: any) {
      setStatusMsg(e?.message || "Action failed.");
      setLoading(false);
    }
  }

  // Failsafe: if pending endpoint returns empty, derive from users where !is_approved
  const pendingDerived = React.useMemo(() => {
    const byEmail = new Map<string, UserRow>();
    for (const u of pending) byEmail.set(u.email.toLowerCase(), u);
    for (const u of users) {
      if (!u.is_approved) byEmail.set((u.email || "").toLowerCase(), u);
    }
    return Array.from(byEmail.values()).sort((a, b) =>
      (b.requested_at || "").localeCompare(a.requested_at || "")
    );
  }, [pending, users]);

  const recentUsers = (overview?.recent_users?.length ? overview.recent_users : users).slice(0, 5);

  return (
<<<<<<< HEAD
    <div className="min-h-screen bg-white text-slate-900">
      <div className="mx-auto max-w-6xl px-6 py-10">
        <div className="flex items-start justify-between gap-6">
          <div>
            <div className="text-sm font-medium text-blue-700">TruthStamp Admin</div>
            <h1 className="mt-1 text-3xl font-semibold tracking-tight">Control Center</h1>
            <p className="mt-2 max-w-2xl text-sm text-slate-600">
              Approve users, view cases, and monitor chain-of-custody events in one place.
            </p>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <Link className="text-slate-700 hover:text-slate-900" href="/">
              Home
            </Link>
            <button
              onClick={() => refreshAll()}
              className="rounded-lg border border-slate-200 bg-white px-3 py-2 font-medium shadow-sm hover:bg-slate-50 disabled:opacity-50"
              disabled={loading}
            >
              Refresh
            </button>
          </div>
        </div>

        <div className="mt-8 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <div className="text-sm font-semibold">Admin Key</div>
              <div className="text-xs text-slate-500">
                Paste your <span className="font-mono">TRUTHSTAMP_ADMIN_API_KEY</span> from Render → truthstamp-api → Environment.
              </div>
            </div>
            <div className="flex w-full flex-col gap-2 md:w-auto md:flex-row md:items-center">
              <input
                value={adminKey}
                onChange={(e) => setAdminKey(e.target.value)}
                placeholder="Paste admin key"
                className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:border-blue-400 md:w-[520px]"
              />
              <div className="flex items-center gap-2">
                <button
                  onClick={saveKey}
                  className="rounded-xl bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-700 disabled:opacity-50"
                  disabled={loading || !adminKey.trim()}
                >
                  Save & Load
                </button>
                <button
                  onClick={clearKey}
                  className="rounded-xl px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100"
                  disabled={loading}
                >
                  Clear
                </button>
              </div>
=======
    <div className="mx-auto w-full max-w-6xl space-y-6 p-6">
      <div className="rounded-2xl border bg-white p-5 shadow-sm">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <div className="text-lg font-semibold">Admin Control Center</div>
            <div className="text-sm text-gray-600">
              Enter your Admin Key to view requests and approve users.
            </div>
          </div>

          <div className="flex w-full flex-col gap-2 md:w-auto md:flex-row md:items-center">
            <input
              value={adminKey}
              onChange={(e) => setAdminKey(e.target.value)}
              placeholder="Admin Key (x-admin-key)"
              className="w-full rounded-xl border px-3 py-2 text-sm md:w-[420px]"
            />
            <Button onClick={saveKey} variant="outline">
              Save Key
            </Button>
            <Button onClick={refreshAll} disabled={loading}>
              {loading ? "Loading..." : "Refresh"}
            </Button>
          </div>
        </div>

        {error ? (
          <div className="mt-3 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </div>
        ) : null}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-2xl border bg-white p-5 shadow-sm">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <div className="text-base font-semibold">Pending requests</div>
              <div className="text-xs text-gray-600">
                Users who submitted the access form and are waiting approval.
              </div>
>>>>>>> 30d16ff (Temp pass)
            </div>
            <div className="text-xs text-gray-500">{pending.length} pending</div>
          </div>

<<<<<<< HEAD
          {statusMsg ? (
            <div
              className={cn(
                "mt-4 rounded-xl border px-3 py-2 text-sm",
                statusMsg === "Loaded."
                  ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                  : statusMsg === "Cleared."
                  ? "border-slate-200 bg-slate-50 text-slate-700"
                  : "border-rose-200 bg-rose-50 text-rose-800"
              )}
            >
              {statusMsg}
            </div>
          ) : null}
        </div>

        <div className="mt-6 grid gap-4 md:grid-cols-3">
          <StatCard
            title="Users"
            value={overview?.counts?.users_total ?? users.length}
            sub={`Pending: ${overview?.counts?.users_pending ?? pendingDerived.length} • Approved: ${overview?.counts?.users_approved ?? users.filter(u => u.is_approved).length}`}
          />
          <StatCard
            title="Cases"
            value={overview?.counts?.cases_total ?? cases.length}
            sub="Total cases in database"
          />
          <StatCard
            title="Evidence"
            value={overview?.counts?.evidence_total ?? 0}
            sub="Uploaded items across all cases"
          />
        </div>

        <div className="mt-6 grid gap-4 md:grid-cols-2">
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="mb-3 flex items-center justify-between">
              <div>
                <div className="text-sm font-semibold">Pending Access Requests</div>
                <div className="text-xs text-slate-500">Users who requested access but are not approved yet.</div>
              </div>
              <div className="text-xs text-slate-500">{pendingDerived.length} pending</div>
            </div>

            {pendingDerived.length === 0 ? (
              <div className="text-sm text-slate-500">No pending requests.</div>
            ) : (
              <div className="divide-y divide-slate-100">
                {pendingDerived.slice(0, 20).map((u) => (
                  <div key={u.email} className="flex items-center justify-between gap-4 py-3">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-medium">{u.name || "—"}</div>
                      <div className="truncate text-xs text-slate-500">{u.email}</div>
                      <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-slate-500">
                        {u.company ? <span className="rounded-full bg-slate-100 px-2 py-0.5">{u.company}</span> : null}
                        {u.occupation ? <span className="rounded-full bg-slate-100 px-2 py-0.5">{u.occupation}</span> : null}
                        {u.phone ? <span className="rounded-full bg-slate-100 px-2 py-0.5">{u.phone}</span> : null}
                      </div>
                    </div>
                    <button
                      onClick={() => setUserFlags(u.email, { is_active: true, is_approved: true })}
                      className="shrink-0 rounded-xl bg-blue-600 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
                      disabled={loading}
                    >
                      Approve & Enable
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="mb-3 flex items-center justify-between">
              <div>
                <div className="text-sm font-semibold">System Snapshot</div>
                <div className="text-xs text-slate-500">Quick view of recent activity.</div>
              </div>
              <div className="text-xs text-slate-500">
                {(overview?.counts?.users_total ?? users.length)} users • {(overview?.counts?.cases_total ?? cases.length)} cases
              </div>
            </div>

            <div className="text-xs font-semibold text-slate-700">Recent Users</div>
            <div className="mt-2 divide-y divide-slate-100 rounded-xl border border-slate-100">
              {recentUsers.length === 0 ? (
                <div className="p-3 text-sm text-slate-500">No users yet.</div>
              ) : (
                recentUsers.map((u) => {
                  const active = !!u.is_active;
                  const approved = !!u.is_approved;
                  return (
                    <div key={u.email} className="flex items-center justify-between gap-3 p-3">
                      <div className="min-w-0">
                        <div className="truncate text-sm font-medium">{u.name || "—"}</div>
                        <div className="truncate text-xs text-slate-500">{u.email}</div>
                        <div className="mt-1 flex gap-2 text-[11px] text-slate-500">
                          <span className={cn("rounded-full px-2 py-0.5", approved ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-700")}>
                            {approved ? "Approved" : "Pending"}
                          </span>
                          <span className={cn("rounded-full px-2 py-0.5", active ? "bg-blue-50 text-blue-700" : "bg-slate-100 text-slate-600")}>
                            {active ? "Active" : "Disabled"}
                          </span>
                        </div>
                      </div>
                      <button
                        onClick={() => setUserFlags(u.email, { is_active: !active, is_approved: approved })}
                        className={cn(
                          "shrink-0 rounded-xl px-3 py-2 text-xs font-semibold disabled:opacity-50",
                          active
                            ? "bg-slate-100 text-slate-800 hover:bg-slate-200"
                            : "bg-blue-600 text-white hover:bg-blue-700"
                        )}
                        disabled={loading}
                      >
                        {active ? "Disable" : "Enable"}
                      </button>
                    </div>
                  );
                })
              )}
            </div>

            <div className="mt-4 text-xs font-semibold text-slate-700">Recent Cases</div>
            <div className="mt-2 rounded-xl border border-slate-100">
              {cases.slice(0, 5).length === 0 ? (
                <div className="p-3 text-sm text-slate-500">No cases yet.</div>
              ) : (
                <div className="divide-y divide-slate-100">
                  {cases.slice(0, 5).map((c) => (
                    <div key={c.id} className="p-3">
                      <div className="text-sm font-medium">{c.title}</div>
                      <div className="mt-1 text-xs text-slate-500">
                        {c.status || "—"} • {c.created_at ? new Date(c.created_at).toLocaleString() : "—"}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="mt-6 text-xs text-slate-500">
          Tip: Keep this admin page private. Anyone with the admin key can approve users and view everything.
=======
          <div className="space-y-3">
            {pending.map((u) => (
              <div key={u.email} className="rounded-xl border p-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-medium">{u.name || "(no name)"}</div>
                    <div className="text-sm text-gray-600">{u.email}</div>
                    <div className="mt-1 text-xs text-gray-500">
                      Requested: {fmt(u.requested_at)}
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      {u.company ? `Company: ${u.company}` : ""}{" "}
                      {u.occupation ? `• ${u.occupation}` : ""}
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-col gap-2">
                    <Button
                      onClick={() => approveAndIssueTemp(u.email)}
                      disabled={loading}
                    >
                      Approve + Temp Password
                    </Button>
                    <Button
                      onClick={() => setActive(u.email, false)}
                      disabled={loading}
                      variant="outline"
                    >
                      Disable
                    </Button>
                  </div>
                </div>
              </div>
            ))}

            {pending.length === 0 ? (
              <div className="rounded-xl border bg-gray-50 p-3 text-sm text-gray-600">
                No pending requests.
              </div>
            ) : null}
          </div>
        </div>

        <div className="rounded-2xl border bg-white p-5 shadow-sm">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <div className="text-base font-semibold">Recent users</div>
              <div className="text-xs text-gray-600">
                Approved + active users appear here.
              </div>
            </div>
            <div className="text-xs text-gray-500">{users.length} total</div>
          </div>

          <div className="space-y-3">
            {users.slice(0, 50).map((u) => (
              <div key={u.email} className="rounded-xl border p-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-medium">{u.name || "(no name)"}</div>
                    <div className="text-sm text-gray-600">{u.email}</div>
                    <div className="mt-1 text-xs text-gray-500">
                      Approved: {fmt(u.approved_at)}
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Active: {u.is_active ? "Yes" : "No"} • Approved:{" "}
                      {u.is_approved ? "Yes" : "No"} • Force change password:{" "}
                      {u.must_change_password ? "Yes" : "No"}
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-col gap-2">
                    {u.is_active ? (
                      <Button
                        onClick={() => setActive(u.email, false)}
                        disabled={loading}
                        variant="outline"
                      >
                        Disable
                      </Button>
                    ) : (
                      <Button
                        onClick={() => setActive(u.email, true)}
                        disabled={loading}
                      >
                        Enable
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            ))}

            {users.length === 0 ? (
              <div className="rounded-xl border bg-gray-50 p-3 text-sm text-gray-600">
                No users loaded. Click Refresh.
              </div>
            ) : null}
          </div>
>>>>>>> 30d16ff (Temp pass)
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, sub }: { title: string; value: number; sub: string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="text-xs font-semibold text-slate-700">{title}</div>
      <div className="mt-1 text-3xl font-semibold tracking-tight">{value}</div>
      <div className="mt-1 text-xs text-slate-500">{sub}</div>
    </div>
  );
}
