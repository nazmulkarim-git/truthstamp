"use client";

import * as React from "react";
import Link from "next/link";

type UserRow = {
  id?: string;
  name?: string;
  email: string;
  phone?: string | null;
  occupation?: string | null;
  company?: string | null;
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
      "x-admin-key": adminKey,
    },
    cache: "no-store",
  });

  if (!res.ok) {
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
  }
  return (await res.json()) as T;
}

export default function AdminClient() {
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
    } finally {
      setLoading(false);
    }
  }

  function saveKey() {
    localStorage.setItem("truthstamp_admin_key", adminKey.trim());
    refreshAll(adminKey.trim());
  }

  function clearKey() {
    localStorage.removeItem("truthstamp_admin_key");
    setAdminKey("");
    setStatusMsg("Cleared.");
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
            </div>
          </div>

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
