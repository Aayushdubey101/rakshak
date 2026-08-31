"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { IntelligenceCore } from "@/components/intelligence-core";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ClickableTableRow } from "@/components/clickable-row";
import type { InvestigationSummary } from "@/lib/mock-data";
import { severityBadgeVariant } from "@/lib/severity";
import { listInvestigations } from "@/lib/api";

export default function DashboardPage() {
  const [all, setAll] = useState<InvestigationSummary[]>([]);

  useEffect(() => {
    listInvestigations(200)
      .then(setAll)
      .catch(() => setAll([]));
  }, []);

  const recent = all.slice(0, 5);
  const threatsDetected = all.filter((i) => i.verdict !== "Safe" && i.verdict !== "Unknown").length;
  const highRisk = all.filter((i) => i.severity === "CRITICAL" || i.severity === "HIGH").length;

  const STATS = [
    { label: "Investigations", value: String(all.length), meta: "All channels" },
    { label: "Threats detected", value: String(threatsDetected), meta: "Across all investigations" },
    { label: "High-risk cases", value: String(highRisk), meta: "Needs attention", accent: true },
    { label: "Channels connected", value: "1/3", meta: "Web · WhatsApp · Telegram" },
  ];

  return (
    <div data-screen-label="dashboard" className="mx-auto max-w-[1180px] px-4 py-10 md:px-6">
      <h6 className="text-[var(--rk-accent-700)]">Rakshak Security Center</h6>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="mb-0.5">Your digital security, powered by AI + ML</h2>
          <p className="m-0 text-[14px] text-muted-rk">3 active protections · last check 2 hours ago</p>
        </div>
        <Button render={<Link href="/analyze" />}>Analyze Something</Button>
      </div>

      <div className="mt-6 grid items-center gap-6 md:grid-cols-[320px_1fr]">
        <Card className="elev-md items-center p-6 text-center">
          <CardContent className="flex flex-col items-center gap-0 p-0">
            <IntelligenceCore size={220} />
            <div className="mt-3 font-heading text-xs font-extrabold tracking-[0.06em] text-[var(--rk-accent-700)]">
              PROTECTION ACTIVE
            </div>
            <p className="mt-1 text-center text-[13px] opacity-80">Detect → Analyze → Correlate → Evaluate → Protect</p>
          </CardContent>
        </Card>
        <div className="grid grid-cols-2 gap-3">
          {STATS.map((stat) => (
            <Card key={stat.label}>
              <CardContent className="flex flex-col gap-0.5">
                <div className="text-[10px] font-extrabold tracking-[0.1em] text-primary uppercase">{stat.label}</div>
                <div className={`font-heading text-[34px] font-extrabold ${stat.accent ? "text-[var(--rk-accent-700)]" : ""}`}>
                  {stat.value}
                </div>
                <div className="text-[11px] text-muted-rk">{stat.meta}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      <div className="mt-6 grid gap-6 md:grid-cols-[1.6fr_1fr]">
        <div className="min-w-0">
          <div className="flex items-baseline justify-between">
            <h4>Recent investigations</h4>
            <Link href="/investigations" className="text-[13px] hover:text-primary">View all →</Link>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Verdict</TableHead>
                <TableHead>Risk</TableHead>
                <TableHead>Date</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {recent.length === 0 && (
                <TableRow><TableCell colSpan={5} className="text-center text-muted-rk">No investigations yet — analyze something to get started.</TableCell></TableRow>
              )}
              {recent.map((inv) => (
                <ClickableTableRow key={inv.id} href={`/reports/${inv.id}`}>
                  <TableCell className="font-heading font-extrabold">{inv.id}</TableCell>
                  <TableCell><Badge variant="tag-neutral">{inv.source}</Badge></TableCell>
                  <TableCell>{inv.verdict}</TableCell>
                  <TableCell><Badge variant={severityBadgeVariant(inv.severity)}>{inv.risk}/100</Badge></TableCell>
                  <TableCell className="text-muted-rk">{inv.date}</TableCell>
                </ClickableTableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <div>
          <h4>Connected channels</h4>
          <div className="flex flex-col gap-2">
            <Card><CardContent className="flex flex-row items-center justify-between"><span className="font-heading text-sm font-extrabold">Web</span><Badge variant="tag-accent">Active</Badge></CardContent></Card>
            <Card><CardContent className="flex flex-row items-center justify-between"><span className="font-heading text-sm font-extrabold">WhatsApp</span><Badge variant="tag-neutral">Not connected</Badge></CardContent></Card>
            <Card><CardContent className="flex flex-row items-center justify-between"><span className="font-heading text-sm font-extrabold">Telegram</span><Badge variant="tag-neutral">Not connected</Badge></CardContent></Card>
          </div>
          <Button variant="outline" className="mt-3 w-full justify-center" render={<Link href="/channels" />}>
            Manage channels
          </Button>
        </div>
      </div>
    </div>
  );
}
