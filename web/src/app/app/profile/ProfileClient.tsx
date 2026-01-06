"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { apiFetch, apiJson } from "@/lib/api";
import { clearToken, getToken } from "@/lib/auth";

type Me = {
  id: string;
  name: string;
  email: string;
  phone?: string | null;
  occupation?: string | null;
  company?: string | null;
  is_approved?: boolean;
  must_change_password?: boolean;
};

export default function ProfileClient() {
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  const [oldPass, setOldPass] = useState("");
  const [newPass, setNewPass] = useState("");
  const [newPass2, setNewPass2] = useState("");

  useEffect(() => {
    const t = getToken();
    if (!t) router.replace("/login");
  }, [router]);

  useEffect(() => {
    (async () => {
      try {
        const data = await apiJson<Me>("/auth/me");
        setMe(data);
      } catch (e: any) {
        setErr(e?.message || "Failed to load profile");
      }
    })();
  }, []);

  async function onChangePassword(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setOk(null);
    if (newPass.length < 8) {
      setErr("Password must be at least 8 characters.");
      return;
    }
    if (newPass !== newPass2) {
      setErr("New passwords do not match.");
      return;
    }

    setBusy(true);
    try {
      const res = await apiFetch("/auth/change-password", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          old_password: oldPass || null,
          new_password: newPass,
        }),
      });
      if (!res.ok) {
        const t = await res.text().catch(() => "");
        throw new Error(t || "Failed to change password");
      }
      setOldPass("");
      setNewPass("");
      setNewPass2("");
      setOk("Password updated.");
      // refresh me state
      try {
        const refreshed = await apiJson<Me>("/auth/me");
        setMe(refreshed);
      } catch {}
    } catch (e: any) {
      setErr(e?.message || "Failed");
    } finally {
      setBusy(false);
    }
  }

  function logout() {
    clearToken();
    router.push("/");
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-white to-blue-50">
      <header className="border-b border-slate-200 bg-white/70 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
          <Link href="/app" className="text-sm font-semibold text-slate-900">
            TruthStamp
          </Link>
          <div className="flex items-center gap-2">
            <Button variant="ghost" asChild className="text-slate-700">
              <Link href="/app">Dashboard</Link>
            </Button>
            <Button variant="outline" onClick={logout}>
              Log out
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-3xl px-4 py-10">
        <div className="mb-6">
          <h1 className="text-2xl font-semibold text-slate-900">Profile</h1>
          <p className="mt-1 text-sm text-slate-600">Manage your account and security.</p>
        </div>

        {err && <div className="mb-4 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">{err}</div>}
        {ok && <div className="mb-4 rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800">{ok}</div>}

        <div className="grid gap-6">
          <Card>
            <CardHeader>
              <CardTitle>Account</CardTitle>
            </CardHeader>
            <CardContent>
              {!me ? (
                <div className="text-sm text-slate-600">Loading…</div>
              ) : (
                <div className="grid gap-3 md:grid-cols-2">
                  <div>
                    <div className="text-xs text-slate-500">Name</div>
                    <div className="text-sm font-medium text-slate-900">{me.name}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500">Email</div>
                    <div className="text-sm font-medium text-slate-900">{me.email}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500">Phone</div>
                    <div className="text-sm text-slate-800">{me.phone || "—"}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500">Occupation</div>
                    <div className="text-sm text-slate-800">{me.occupation || "—"}</div>
                  </div>
                  <div className="md:col-span-2">
                    <div className="text-xs text-slate-500">Company</div>
                    <div className="text-sm text-slate-800">{me.company || "—"}</div>
                  </div>

                  {me.must_change_password ? (
                    <div className="md:col-span-2 mt-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                      ⚠️ You are using a temporary password. Please change it now.
                    </div>
                  ) : null}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Change password</CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={onChangePassword} className="space-y-4">
                <div className="grid gap-3 md:grid-cols-2">
                  <div className="space-y-1">
                    <label className="text-sm text-slate-700">Current password</label>
                    <Input
                      value={oldPass}
                      onChange={(e) => setOldPass(e.target.value)}
                      type="password"
                      placeholder={me?.must_change_password ? "Not required for temp password" : ""}
                    />
                    {me?.must_change_password ? (
                      <p className="text-xs text-slate-500">If you logged in with a temporary password, you can leave this blank.</p>
                    ) : null}
                  </div>
                  <div />
                  <div className="space-y-1">
                    <label className="text-sm text-slate-700">New password</label>
                    <Input value={newPass} onChange={(e) => setNewPass(e.target.value)} type="password" required />
                  </div>
                  <div className="space-y-1">
                    <label className="text-sm text-slate-700">Confirm new password</label>
                    <Input value={newPass2} onChange={(e) => setNewPass2(e.target.value)} type="password" required />
                  </div>
                </div>

                <Button disabled={busy} type="submit" className="bg-blue-600 hover:bg-blue-700">
                  {busy ? "Updating…" : "Update password"}
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
