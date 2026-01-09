"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";

type UserRow = {
  id?: string;
  name?: string;
  email?: string;
  phone?: string;
  occupation?: string;
  company?: string;
  is_active?: boolean;
  is_approved?: boolean;
  must_change_password?: boolean;
  requested_at?: string;
  approved_at?: string;
};

type CaseRow = {
  id: string;
  title?: string;
  status?: string;
  created_at?: string;
  user_id?: string;
};

const API_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ||
  "http://localhost:8000";

function fmtDate(s?: string) {
  if (!s) return "";
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleString();
}

export default function AdminClient() {
  const [adminKey, setAdminKey] = useState("");
  const [savingKey, setSavingKey] = useState(false);

  const [overview, setOverview] = useState<any>(null);
  const [pending, setPending] = useState<UserRow[]>([]);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [cases, setCases] = useState<CaseRow[]>([]);
  const [status, setStatus] = useState<string>("all");

  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState<string>("");

  // Load key from localStorage (client-only)
  useEffect(() => {
    const k = localStorage.getItem("truthstamp_admin_key") || "";
    setAdminKey(k);
  }, []);

  const headers = useMemo(() => {
    return {
      "Content-Type": "application/json",
      "x-admin-key": adminKey || "",
    };
  }, [adminKey]);

  async function api<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: { ...(init?.headers || {}), ...headers },
      cache: "no-store",
    });

    // helpful error text
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`${res.status} ${res.statusText}${text ? ` — ${text}` : ""}`);
    }
    return (await res.json()) as T;
  }

  async function refreshAll() {
    if (!adminKey) {
      setMsg("Enter admin key first.");
      return;
    }
    setLoading(true);
    setMsg("");
    try {
      const ov = await api<any>("/admin/overview");
      setOverview(ov);

      const pend = await api<UserRow[]>("/admin/pending-users");
      setPending(pend || []);

      const us = await api<UserRow[]>(`/admin/users?status=${encodeURIComponent(status)}`);
      setUsers(us || []);

      const cs = await api<CaseRow[]>("/admin/cases");
      setCases(cs || []);
    } catch (e: any) {
      setMsg(e?.message || "Failed to fetch admin data");
    } finally {
      setLoading(false);
    }
  }

  async function saveKey() {
    setSavingKey(true);
    try {
      localStorage.setItem("truthstamp_admin_key", adminKey || "");
      setMsg("Admin key saved. Now refresh.");
    } finally {
      setSavingKey(false);
    }
  }

  // One endpoint that updates a user by email (no more undefined IDs)
  async function updateUserByEmail(email: string, patch: { is_active?: boolean; is_approved?: boolean }) {
    if (!email) {
      setMsg("Missing email for user.");
      return;
    }
    setLoading(true);
    setMsg("");
    try {
      await api("/admin/users/enable-by-email", {
        method: "POST",
        body: JSON.stringify({ email, ...patch }),
      });
      await refreshAll();
      setMsg(`Updated user: ${email}`);
    } catch (e: any) {
      setMsg(e?.message || "Update failed");
    } finally {
      setLoading(false);
    }
  }

  // Generate + email a temporary password (forced password change)
  async function sendTempPassword(email: string) {
    if (!email) {
      setMsg("Missing email for user.");
      return;
    }
    setLoading(true);
    setMsg("");
    try {
      const out = await api<{ ok: boolean; temp_password?: string }>(
        "/admin/users/send-temp-password",
        {
          method: "POST",
          body: JSON.stringify({ email }),
        }
      );

      // In production you should NOT show temp password in UI.
      // But for now, if SMTP isn’t configured, backend returns it so you can manually message the user.
      if (out?.temp_password) {
        setMsg(`Temp password generated for ${email}: ${out.temp_password}`);
      } else {
        setMsg(`Temp password email sent to ${email} (if SMTP configured).`);
      }

      await refreshAll();
    } catch (e: any) {
      setMsg(e?.message || "Temp password failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-6xl px-4 py-10">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Admin Control Center</h1>
          <p className="text-sm text-gray-500">
            API: <span className="font-mono">{API_URL}</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link className="text-sm underline" href="/">
            Home
          </Link>
        </div>
      </div>

      <div className="mt-6 rounded-xl border bg-white p-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div className="w-full">
            <label className="text-sm font-medium">Admin Key</label>
            <input
              className="mt-1 w-full rounded-lg border px-3 py-2 font-mono text-sm"
              placeholder="Paste TRUTHSTAMP_ADMIN_API_KEY here"
              value={adminKey}
              onChange={(e) => setAdminKey(e.target.value)}
            />
          </div>
          <div className="flex gap-2">
            <Button onClick={saveKey} disabled={savingKey}>
              Save Key
            </Button>
            <Button onClick={refreshAll} disabled={loading || !adminKey}>
              {loading ? "Loading..." : "Refresh"}
            </Button>
          </div>
        </div>

        {msg ? (
          <div className="mt-3 rounded-lg bg-gray-50 px-3 py-2 text-sm">{msg}</div>
        ) : null}
      </div>

      {/* Overview */}
      <div className="mt-6 grid gap-4 md:grid-cols-3">
        <div className="rounded-xl border bg-white p-4">
          <div className="text-sm text-gray-500">Users</div>
          <div className="mt-1 text-2xl font-semibold">
            {overview?.counts?.users_total ?? "—"}
          </div>
          <div className="mt-2 text-xs text-gray-500">
            Pending: {overview?.counts?.users_pending ?? "—"} • Approved:{" "}
            {overview?.counts?.users_approved ?? "—"}
          </div>
        </div>

        <div className="rounded-xl border bg-white p-4">
          <div className="text-sm text-gray-500">Cases</div>
          <div className="mt-1 text-2xl font-semibold">
            {overview?.counts?.cases_total ?? "—"}
          </div>
        </div>

        <div className="rounded-xl border bg-white p-4">
          <div className="text-sm text-gray-500">Evidence</div>
          <div className="mt-1 text-2xl font-semibold">
            {overview?.counts?.evidence_total ?? "—"}
          </div>
        </div>
      </div>

      {/* Pending */}
      <div className="mt-6 rounded-xl border bg-white p-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold">Pending Requests</h2>
          <div className="text-xs text-gray-500">
            Tip: Approve → Send Temp Password
          </div>
        </div>

        <div className="mt-4 overflow-auto">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead>
              <tr className="border-b text-xs text-gray-500">
                <th className="py-2">Name</th>
                <th>Email</th>
                <th>Company</th>
                <th>Requested</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {pending.length === 0 ? (
                <tr>
                  <td className="py-6 text-gray-500" colSpan={5}>
                    No pending users.
                  </td>
                </tr>
              ) : (
                pending.map((u) => (
                  <tr key={u.email || u.id} className="border-b">
                    <td className="py-3">{u.name || "—"}</td>
                    <td className="font-mono text-xs">{u.email || "—"}</td>
                    <td>{u.company || "—"}</td>
                    <td className="text-xs text-gray-500">{fmtDate(u.requested_at)}</td>
                    <td className="py-3">
                      <div className="flex justify-end gap-2">
                        <Button
                          onClick={() =>
                            updateUserByEmail(u.email || "", { is_approved: true, is_active: true })
                          }
                          disabled={loading}
                        >
                          Approve
                        </Button>
                        <Button
                          onClick={() => sendTempPassword(u.email || "")}
                          disabled={loading}
                          className="bg-blue-600 hover:bg-blue-700"
                        >
                          Send Temp Password
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Users */}
      <div className="mt-6 rounded-xl border bg-white p-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <h2 className="text-lg font-semibold">Users</h2>

          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-600">Filter:</label>
            <select
              className="rounded-lg border px-2 py-2 text-sm"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="all">All</option>
              <option value="approved">Approved</option>
              <option value="pending">Pending</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>
            <Button onClick={refreshAll} disabled={loading || !adminKey}>
              Apply
            </Button>
          </div>
        </div>

        <div className="mt-4 overflow-auto">
          <table className="w-full min-w-[1000px] text-left text-sm">
            <thead>
              <tr className="border-b text-xs text-gray-500">
                <th className="py-2">Name</th>
                <th>Email</th>
                <th>Status</th>
                <th>Requested</th>
                <th>Approved</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.length === 0 ? (
                <tr>
                  <td className="py-6 text-gray-500" colSpan={6}>
                    No users.
                  </td>
                </tr>
              ) : (
                users.map((u) => {
                  const email = u.email || "";
                  return (
                    <tr key={email || u.id} className="border-b">
                      <td className="py-3">{u.name || "—"}</td>
                      <td className="font-mono text-xs">{email || "—"}</td>
                      <td className="text-xs">
                        <div className="flex flex-wrap gap-2">
                          <span>approved: {String(!!u.is_approved)}</span>
                          <span>active: {String(!!u.is_active)}</span>
                          <span>forceChange: {String(!!u.must_change_password)}</span>
                        </div>
                      </td>
                      <td className="text-xs text-gray-500">{fmtDate(u.requested_at)}</td>
                      <td className="text-xs text-gray-500">{fmtDate(u.approved_at)}</td>
                      <td className="py-3">
                        <div className="flex justify-end gap-2">
                          <Button
                            onClick={() => updateUserByEmail(email, { is_active: true })}
                            disabled={loading || !email}
                          >
                            Enable
                          </Button>
                          <Button
                            onClick={() => updateUserByEmail(email, { is_active: false })}
                            disabled={loading || !email}
                            variant="secondary"
                          >
                            Disable
                          </Button>
                          <Button
                            onClick={() => sendTempPassword(email)}
                            disabled={loading || !email}
                            className="bg-blue-600 hover:bg-blue-700"
                          >
                            Temp Password
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Cases */}
      <div className="mt-6 rounded-xl border bg-white p-4">
        <h2 className="text-lg font-semibold">Cases</h2>
        <div className="mt-4 overflow-auto">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead>
              <tr className="border-b text-xs text-gray-500">
                <th className="py-2">ID</th>
                <th>Title</th>
                <th>Status</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {cases.length === 0 ? (
                <tr>
                  <td className="py-6 text-gray-500" colSpan={4}>
                    No cases.
                  </td>
                </tr>
              ) : (
                cases.map((c) => (
                  <tr key={c.id} className="border-b">
                    <td className="py-3 font-mono text-xs">{c.id}</td>
                    <td>{c.title || "—"}</td>
                    <td className="text-xs">{c.status || "—"}</td>
                    <td className="text-xs text-gray-500">{fmtDate(c.created_at)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="mt-8 text-xs text-gray-500">
        If SMTP is not configured, the backend will return the generated temp password so you can
        manually send it. Once SMTP is configured, it will email users.
      </div>
    </div>
  );
}
