"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { apiFetch } from "@/lib/api";

export default function RegisterClient() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [occupation, setOccupation] = useState("");
  const [company, setCompany] = useState("");
  const [useCase, setUseCase] = useState("");

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const res = await apiFetch("/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name,
          email,
          phone,
          occupation,
          company,
          use_case: useCase,
          role: occupation || null,
          notes: null,
        }),
      });
      if (!res.ok) {
        const t = await res.text().catch(() => "");
        throw new Error(t || "Request failed");
      }
      setOk(true);
      // stay on page; allow user to go to login
    } catch (e: any) {
      setErr(e?.message || "Failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-white to-blue-50">
      <div className="mx-auto flex max-w-xl flex-col gap-6 px-4 py-16">
        <div>
          <Link href="/" className="text-sm text-slate-600 hover:text-slate-900">
            ← Back to TruthStamp
          </Link>
          <h1 className="mt-4 text-3xl font-semibold text-slate-900">Request access</h1>
          <p className="mt-2 text-sm text-slate-600">
            TruthStamp is invite-only for evidence-grade workflows. Submit your details — we&apos;ll email you a temporary password after review.
          </p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Your details</CardTitle>
          </CardHeader>
          <CardContent>
            {ok ? (
              <div className="space-y-3">
                <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm text-blue-800">
                  ✅ Request received. If approved, you&apos;ll receive a temporary password at <b>{email}</b>.
                </div>
                <div className="flex gap-3">
                  <Button onClick={() => router.push("/login")} className="bg-blue-600 hover:bg-blue-700">
                    Go to login
                  </Button>
                  <Button variant="outline" onClick={() => router.push("/")}>
                    Home
                  </Button>
                </div>
              </div>
            ) : (
              <form onSubmit={onSubmit} className="space-y-4">
                <div className="grid gap-3 md:grid-cols-2">
                  <div className="space-y-1">
                    <label className="text-sm text-slate-700">Full name</label>
                    <Input value={name} onChange={(e) => setName(e.target.value)} required />
                  </div>
                  <div className="space-y-1">
                    <label className="text-sm text-slate-700">Email</label>
                    <Input value={email} onChange={(e) => setEmail(e.target.value)} type="email" required />
                  </div>
                  <div className="space-y-1">
                    <label className="text-sm text-slate-700">Phone</label>
                    <Input value={phone} onChange={(e) => setPhone(e.target.value)} />
                  </div>
                  <div className="space-y-1">
                    <label className="text-sm text-slate-700">Occupation</label>
                    <Input value={occupation} onChange={(e) => setOccupation(e.target.value)} placeholder="e.g., Lawyer, Journalist" />
                  </div>
                  <div className="space-y-1 md:col-span-2">
                    <label className="text-sm text-slate-700">Company / Organization</label>
                    <Input value={company} onChange={(e) => setCompany(e.target.value)} />
                  </div>
                  <div className="space-y-1 md:col-span-2">
                    <label className="text-sm text-slate-700">Primary use case</label>
                    <Input value={useCase} onChange={(e) => setUseCase(e.target.value)} placeholder="e.g., court evidence, newsroom verification, compliance" />
                  </div>
                </div>

                {err && <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">{err}</div>}

                <Button disabled={busy} type="submit" className="w-full bg-blue-600 hover:bg-blue-700">
                  {busy ? "Submitting…" : "Request access"}
                </Button>

                <p className="text-xs text-slate-500">
                  Already have credentials?{" "}
                  <Link className="text-blue-700 hover:underline" href="/login">
                    Log in
                  </Link>
                  .
                </p>
              </form>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
