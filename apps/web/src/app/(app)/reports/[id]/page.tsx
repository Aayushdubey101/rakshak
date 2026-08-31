"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { severityBadgeVariant, scoreColorClass } from "@/lib/severity";
import { getInvestigation, ApiError } from "@/lib/api";
import type { FullReport } from "@/lib/mock-data";

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const [report, setReport] = useState<FullReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getInvestigation(id)
      .then((r) => !cancelled && setReport(r))
      .catch((err) => !cancelled && setError(err instanceof ApiError ? err.message : "Could not load this report"));
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (error) {
    return <div className="mx-auto max-w-[920px] px-4 py-10 text-center text-sm text-destructive md:px-6">{error}</div>;
  }
  if (!report) {
    return <div className="mx-auto max-w-[920px] px-4 py-10 text-center text-sm text-muted-rk md:px-6">Loading report…</div>;
  }

  return (
    <div data-screen-label="report" className="mx-auto max-w-[920px] px-4 py-10 md:px-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h6 className="text-[var(--rk-accent-700)]">Investigation {report.id}</h6>
          <h1 className="mb-1">{report.verdict}</h1>
          <div className="flex items-center gap-2">
            <Badge variant={severityBadgeVariant(report.severity)}>{report.severity} RISK</Badge>
            <span className="text-[13px] text-muted-rk">{report.confidence}% confidence</span>
          </div>
        </div>
        <div className="text-right">
          <div className={`font-heading text-[56px] leading-none font-extrabold ${scoreColorClass(report.score)}`}>
            {report.score}<span className="text-[22px] opacity-50">/100</span>
          </div>
          <Progress value={report.score} className="mt-1.5 h-1.5 w-[200px]" />
        </div>
      </div>

      <hr className="my-6 h-0.5 border-0 bg-border" />

      <h4>Why Rakshak flagged this</h4>
      <p className="max-w-[640px] text-sm">{report.reason}</p>

      <h4 className="mt-6">Threat signals</h4>
      <div className="flex flex-col gap-3">
        {report.signals.map((sig) => (
          <div key={sig.label}>
            <div className="mb-1 flex justify-between text-[13px]"><span>{sig.label}</span><span className="text-muted-rk">{sig.pct}%</span></div>
            <Progress value={sig.pct} className="h-1.5" />
          </div>
        ))}
      </div>

      <div className="mt-6 grid gap-6 md:grid-cols-2">
        <div>
          <h4>ML findings</h4>
          <ul className="m-0 pl-[18px] text-[13px]">
            {report.mlFindings.map((f) => <li key={f} className="mb-1.5">{f}</li>)}
          </ul>
        </div>
        <div>
          <h4>Cybersecurity findings</h4>
          <ul className="m-0 pl-[18px] text-[13px]">
            {report.cyberFindings.map((f) => <li key={f} className="mb-1.5">{f}</li>)}
          </ul>
        </div>
      </div>

      <h4 className="mt-6">Extracted entities</h4>
      <div className="flex flex-wrap gap-2">
        {report.entities.length
          ? report.entities.map((e) => <Badge key={e} variant="tag-outline">{e}</Badge>)
          : <span className="text-[13px] text-muted-rk">No entities extracted</span>}
      </div>

      {report.domains.length > 0 && (
        <>
          <h4 className="mt-6">URL / domain analysis</h4>
          <Table>
            <TableHeader>
              <TableRow><TableHead>Domain</TableHead><TableHead>Registered</TableHead><TableHead>Reputation</TableHead><TableHead>Related campaign</TableHead></TableRow>
            </TableHeader>
            <TableBody>
              {report.domains.map((d) => (
                <TableRow key={d.domain}>
                  <TableCell className="font-heading">{d.domain}</TableCell>
                  <TableCell>{d.registered}</TableCell>
                  <TableCell>{d.reputation}</TableCell>
                  <TableCell>{d.campaign}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </>
      )}

      {report.campaignId && (
        <>
          <h4 className="mt-6">Threat intelligence — related campaign</h4>
          <Link href={`/threat-intel/campaigns/${report.campaignId}`}>
            <Card className="elev-sm cursor-pointer">
              <CardContent className="flex flex-col gap-1">
                <div className="font-heading text-[17px] font-extrabold">View related campaign →</div>
              </CardContent>
            </Card>
          </Link>
        </>
      )}

      <h4 className="mt-6">Investigation timeline</h4>
      <div className="flex flex-col">
        {report.timeline.map((t, i) => (
          <div key={`${t.time}-${i}`} className="flex gap-3 border-b border-border py-1.5 text-[13px]">
            <span className="w-[90px] flex-none text-muted-rk">{t.time}</span><span>{t.text}</span>
          </div>
        ))}
      </div>

      <h4 className="mt-6">Recommended actions</h4>
      <ul className="pl-[18px] text-sm">
        {report.actions.map((a) => <li key={a} className="mb-1.5">{a}</li>)}
      </ul>

      <h4 className="mt-6">AI explanation</h4>
      <Card className="bg-muted"><CardContent><p className="text-[13px] opacity-80">{report.aiExplanation}</p></CardContent></Card>

      <hr className="my-6 h-0.5 border-0 bg-border" />
      <h4>Preview: short report sent to WhatsApp / Telegram</h4>
      <div className="max-w-[340px] whitespace-pre-line bg-[var(--rk-neutral-900)] p-4 font-mono text-[13px] leading-relaxed text-[#f8f4f4]">
        {`🔴 RAKSHAK ALERT\n\n${report.verdict}\n\nRisk: ${report.score}/100\nSeverity: ${report.severity}\n\n⚠ ${report.signals[0].label}\n⚠ ${report.signals[1].label}\n\nDO NOT CLICK THE LINK.\n\nView Full Report →`}
      </div>
    </div>
  );
}
