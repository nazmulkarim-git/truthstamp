"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { setToken } from "@/lib/auth";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:10000";

export default function LoginClient() {
  const router = useRouter();
  const next = "/app";
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!r.ok) throw new Error(await r.text());
      const data = await r.json();
      setToken(data.token);
      if (data?.user?.must_change_password) {
        router.replace("/app/profile");
      } else {
        router.replace(next);
      }
    } catch (err: any) {
      setError(err?.message || "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="mb-6 text-center">
          <div className="text-xs font-medium text-blue-700">TruthStamp</div>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight">Sign in</h1>
          <p className="mt-2 text-sm text-slate-600">
            Evidence workspace · Cases · Chain of custody
          </p>
        </div>

        <Card className="p-6 shadow-sm border-slate-200">
          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <div className="text-sm font-medium mb-1">Email</div>
              <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@domain.com" />
            </div>
            <div>
              <div className="text-sm font-medium mb-1">Password</div>
              <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
            </div>

            {error && (
              <div className="text-sm text-red-600 border border-red-200 bg-red-50 rounded-md p-2">
                {error}
              </div>
            )}

            <Button disabled={busy} type="submit" className="w-full">
              {busy ? "Signing in…" : "Sign in"}
            </Button>

            <div className="text-sm text-slate-600 text-center">
              New here?{" "}
              <a className="text-blue-700 hover:underline" href="/register">
                Create an account
              </a>
            </div>
          </form>
        </Card>

        <div className="mt-6 text-xs text-slate-500 text-center">
          Provenance-first. No guessing. Court/claims-grade chain of custody.
        </div>
      </div>
    </div>
  );
}
