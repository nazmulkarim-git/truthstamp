"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/api";
import { clearToken, getToken } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";

type CaseItem = { id: string; title: string; description?: string | null; created_at: string };

export default function Dashboard() {
  const router = useRouter();
  const [cases, setCases] = useState<CaseItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [title, setTitle] = useState("");
  const [desc, setDesc] = useState("");
  const [err, setErr] = useState<string | null>(null);

  async function loadCases() {
    setLoading(true);
    setErr(null);
    try {
      const r = await apiFetch("/cases");
      if (!r.ok) throw new Error(await r.text());
      const data = (await r.json()) as CaseItem[];
      setCases(data);
    } catch (e: any) {
      setErr(e?.message || "Failed to load cases");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!getToken()) router.replace("/login");
    loadCases();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function createCase() {
    setErr(null);
    try {
      const r = await apiFetch("/cases", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ title, description: desc || null }),
      });
      if (!r.ok) throw new Error(await r.text());
      const c = (await r.json()) as CaseItem;
      setTitle("");
      setDesc("");
      await loadCases();
      router.push(`/app/cases/${c.id}`);
    } catch (e: any) {
      setErr(e?.message || "Failed to create case");
    }
  }

  function signOut() {
    clearToken();
    router.replace("/login");
  }

  return (
    <div className="min-h-screen bg-white">
      <div className="max-w-6xl mx-auto px-4 py-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-blue-700">TruthStamp</div>
            <h1 className="text-2xl font-semibold tracking-tight">Evidence Workspace</h1>
            <p className="mt-1 text-sm text-slate-600">
              Organize any photo/video as evidence. Build chain-of-custody. Generate decision-grade reports.
            </p>
          </div>
          <Button variant="secondary" onClick={signOut}>
            Sign out
          </Button>
        </div>

        <Separator className="my-6" />

        <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
          {/* Sidebar */}
          <div className="md:col-span-4">
            <Card className="p-4 border-slate-200 shadow-sm">
              <div className="flex items-center justify-between">
                <div className="text-sm font-semibold">Your cases</div>
                <div className="text-xs text-slate-500">{loading ? "…" : `${cases.length}`}</div>
              </div>

              <div className="mt-3 space-y-1">
                {cases.map((c) => (
                  <button
                    key={c.id}
                    onClick={() => router.push(`/app/cases/${c.id}`)}
                    className="w-full text-left rounded-md px-3 py-2 hover:bg-slate-50 border border-transparent hover:border-slate-200 transition"
                  >
                    <div className="text-sm font-medium text-slate-900">{c.title}</div>
                    <div className="text-xs text-slate-500 truncate">{c.description || "No description"}</div>
                  </button>
                ))}
                {!loading && cases.length === 0 && (
                  <div className="text-sm text-slate-600 py-6 text-center">
                    No cases yet. Create your first case.
                  </div>
                )}
              </div>
            </Card>
          </div>

          {/* Main */}
          <div className="md:col-span-8">
            <Card className="p-6 border-slate-200 shadow-sm">
              <div className="text-sm font-semibold">Create a new case</div>
              <p className="mt-1 text-sm text-slate-600">
                Examples: “Court Exhibit A”, “Journalism – source verification”, “HR incident report”, “Insurance claim #…”.
              </p>

              <div className="mt-4 grid gap-3">
                <div>
                  <div className="text-sm font-medium mb-1">Title</div>
                  <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Case title" />
                </div>
                <div>
                  <div className="text-sm font-medium mb-1">Description (optional)</div>
                  <Input value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="Short context" />
                </div>

                {err && (
                  <div className="text-sm text-red-600 border border-red-200 bg-red-50 rounded-md p-2">
                    {err}
                  </div>
                )}

                <div className="flex gap-2">
                  <Button onClick={createCase} disabled={!title.trim()}>
                    Create case
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => router.push(cases[0] ? `/app/cases/${cases[0].id}` : "/app")}
                    disabled={!cases.length}
                  >
                    Open latest
                  </Button>
                </div>

                <div className="mt-3 text-xs text-slate-500">
                  YC signal: cases + chain-of-custody makes TruthStamp a system of record, not a metadata viewer.
                </div>
              </div>
            </Card>

            <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Card className="p-5 border-slate-200 shadow-sm">
                <div className="text-sm font-semibold">Verifiable</div>
                <p className="mt-1 text-sm text-slate-600">
                  Cryptographic provenance (C2PA) when present — camera/app signatures, issuer, edits.
                </p>
              </Card>
              <Card className="p-5 border-slate-200 shadow-sm">
                <div className="text-sm font-semibold">Chain-of-custody</div>
                <p className="mt-1 text-sm text-slate-600">
                  Every upload, analysis, and report is logged. Exportable and auditable.
                </p>
              </Card>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
