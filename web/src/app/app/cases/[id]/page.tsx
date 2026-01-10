"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { apiFetch, apiJson } from "@/lib/api";

type Case = {
  id: string;
  title: string;
  description?: string | null;
  status: string;
  created_at?: string | null;
};

type Evidence = {
  id: string;
  filename: string;
  sha256: string;
  media_type?: string | null;
  bytes?: number | null;
  provenance_state?: string | null;
  summary?: string | null;
  created_at?: string | null;
};

type Event = {
  id: string;
  event_type: string;
  actor?: string | null;
  created_at?: string | null;
};

export default function CasePage() {
  const params = useParams<{ id: string }>();
  const caseId = params?.id as string;

  const [caze, setCase] = useState<Case | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [file, setFile] = useState<File | null>(null);

  async function refresh() {
    setErr(null);
    try {
      const c = await apiJson<Case>(`/cases/${caseId}`);
      const ev = await apiJson<Evidence[]>(`/cases/${caseId}/evidence`);
      const evs = await apiJson<Event[]>(`/cases/${caseId}/events?limit=50`);
      setCase(c);
      setEvidence(ev);
      setEvents(evs);
    } catch (e: any) {
      setErr(e?.message || "Failed to load case");
    }
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId]);

  async function uploadAndAnalyze() {
  if (!file) return;
  setBusy(true);
  setErr(null);

  try {
    const fd = new FormData();
    fd.append("file", file);

    // IMPORTANT: call the case evidence endpoint (this stores to DB)
    const res = await apiFetch(`/cases/${caseId}/evidence`, {
      method: "POST",
      body: fd,
    });

    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(t || "Upload + Analyze failed");
    }

    await refresh();   // reload case + evidence + events
    setFile(null);
  } catch (e: any) {
    setErr(e?.message || "Failed");
  } finally {
    setBusy(false);
  }
}

  async function generateReport() {
    setBusy(true);
    try {
      const res = await apiFetch("/report", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/pdf",
        },
        body: JSON.stringify({ case_id: caseId }),
      });

      if (!res.ok) {
        // show useful error message (backend returns JSON detail on 4xx)
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `truthstamp_report_${caseId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);

      toast({ title: "Report downloaded" });
    } catch (e: any) {
      toast({
        title: "Report failed",
        description: e?.message?.slice(0, 300) || "Unknown error",
        variant: "destructive",
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-white to-blue-50">
      <header className="border-b border-slate-200 bg-white/70 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
          <Link href="/app" className="text-sm font-semibold text-slate-900">
            TruthStamp
          </Link>
          <Button variant="outline" asChild>
            <Link href="/app">Back to cases</Link>
          </Button>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-10">
        {err ? (
          <div className="mb-4 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">{err}</div>
        ) : null}

        <div className="grid gap-6 md:grid-cols-3">
          <div className="md:col-span-2 space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>{caze ? caze.title : "Loading…"}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline">Case</Badge>
                  {caze?.status ? <Badge>{caze.status}</Badge> : null}
                  {caze?.created_at ? <span className="text-xs text-slate-500">Created {new Date(caze.created_at).toLocaleString()}</span> : null}
                </div>
                {caze?.description ? <p className="mt-3 text-sm text-slate-700">{caze.description}</p> : null}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Evidence</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col gap-3">
                  {evidence.length === 0 ? (
                    <div className="text-sm text-slate-600">No evidence yet. Upload a file to begin.</div>
                  ) : (
                    evidence.map((e) => (
                      <div key={e.id} className="rounded-lg border border-slate-200 p-3">
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <div className="text-sm font-medium text-slate-900">{e.filename}</div>
                            <div className="mt-1 text-xs text-slate-600 break-all">SHA-256: {e.sha256}</div>
                            {e.summary ? <div className="mt-2 text-sm text-slate-700">{e.summary}</div> : null}
                          </div>
                          <div className="flex flex-col items-end gap-2">
                            {e.provenance_state ? <Badge>{e.provenance_state}</Badge> : null}
                            {e.created_at ? <div className="text-xs text-slate-500">{new Date(e.created_at).toLocaleString()}</div> : null}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Upload</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="space-y-1">
                  <label className="text-sm text-slate-700">Select file (image or video)</label>
                  <Input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} />
                </div>

                <div className="grid gap-2">
                  <Button disabled={!file || busy} onClick={uploadAndAnalyze} className="bg-blue-600 hover:bg-blue-700">
                    {busy ? "Working…" : "Add to case + Analyze"}
                  </Button>
                  <Button disabled={busy} onClick={generateReport} variant="outline">
                    Generate Report
                  </Button>
                </div>

                <p className="text-xs text-slate-500">
                  Tip: “Analyze” stores structured metadata + chain-of-custody events. PDF creates a shareable court-ready report.
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Chain of custody</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {events.length === 0 ? (
                    <div className="text-sm text-slate-600">No events yet.</div>
                  ) : (
                    events.map((ev) => (
                      <div key={ev.id} className="flex items-start justify-between gap-2 rounded-md border border-slate-200 p-2">
                        <div>
                          <div className="text-sm font-medium text-slate-900">{ev.event_type}</div>
                          <div className="text-xs text-slate-600">{ev.actor || "user"}</div>
                        </div>
                        <div className="text-xs text-slate-500">{ev.created_at ? new Date(ev.created_at).toLocaleString() : ""}</div>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Admin</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-slate-700">
                <p className="text-sm text-slate-600">
                  To approve users, call <code className="rounded bg-slate-100 px-1 py-0.5">/admin/pending-users</code> and{" "}
                  <code className="rounded bg-slate-100 px-1 py-0.5">/admin/approve-user</code> with header{" "}
                  <code className="rounded bg-slate-100 px-1 py-0.5">X-Admin-Key</code>.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}
