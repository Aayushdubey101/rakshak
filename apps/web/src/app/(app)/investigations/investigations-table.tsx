"use client";

import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ClickableTableRow } from "@/components/clickable-row";
import type { InvestigationSummary, Source } from "@/lib/mock-data";
import { severityBadgeVariant } from "@/lib/severity";
import { listInvestigations } from "@/lib/api";

const FILTERS: { label: string; value: Source | "ALL" }[] = [
  { label: "All sources", value: "ALL" },
  { label: "Web", value: "WEB" },
  { label: "WhatsApp", value: "WHATSAPP" },
  { label: "Telegram", value: "TELEGRAM" },
];

export function InvestigationsTable() {
  const [filter, setFilter] = useState<Source | "ALL">("ALL");
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);

  useEffect(() => {
    listInvestigations()
      .then(setInvestigations)
      .catch(() => setInvestigations([]));
  }, []);

  const filtered = investigations.filter((inv) => filter === "ALL" || inv.source === filter);

  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-2">
        {FILTERS.map((f) => (
          <Button key={f.value} variant={filter === f.value ? "default" : "outline"} onClick={() => setFilter(f.value)}>
            {f.label}
          </Button>
        ))}
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>ID</TableHead>
            <TableHead>Source</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Verdict</TableHead>
            <TableHead>Risk</TableHead>
            <TableHead>Date</TableHead>
            <TableHead>Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filtered.length === 0 && (
            <TableRow><TableCell colSpan={7} className="text-center text-muted-rk">No investigations yet.</TableCell></TableRow>
          )}
          {filtered.map((inv) => (
            <ClickableTableRow key={inv.id} href={`/reports/${inv.id}`}>
              <TableCell className="font-heading font-extrabold">{inv.id}</TableCell>
              <TableCell><Badge variant="tag-neutral">{inv.source}</Badge></TableCell>
              <TableCell>{inv.type}</TableCell>
              <TableCell>{inv.verdict}</TableCell>
              <TableCell><Badge variant={severityBadgeVariant(inv.severity)}>{inv.risk}/100</Badge></TableCell>
              <TableCell className="text-muted-rk">{inv.date}</TableCell>
              <TableCell className="text-muted-rk">{inv.status}</TableCell>
            </ClickableTableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
