"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { campaigns, entities } from "@/lib/mock-data";
import { getScamFeed, type ScamFeedEntry } from "@/lib/api";

const SAFETY_TIPS = [
  "Never share OTPs, UPI PINs, or card CVVs — no bank, courier, or “officer” will ever ask for these over call/message.",
  "Verify unfamiliar payment links or QR codes by typing the site's known URL yourself instead of tapping a shared link.",
  "Treat urgency (“account frozen,” “digital arrest,” “package held”) as a red flag — legitimate agencies don't force instant action.",
  "Confirm any “refund” or “prize” claim by contacting the company directly through its official app or number, not a number the message gave you.",
];

export default function ThreatIntelPage() {
  const [feed, setFeed] = useState<ScamFeedEntry[]>([]);

  useEffect(() => {
    getScamFeed()
      .then(setFeed)
      .catch(() => setFeed([]));
  }, []);

  return (
    <div data-screen-label="threat-intelligence" className="mx-auto max-w-[1080px] px-4 py-10 md:px-6">
      <h6 className="text-[var(--rk-accent-700)]">Threat Intelligence</h6>
      <h2>Domains, entities & campaigns</h2>
      <Input placeholder="Search domains, phone numbers, UPI IDs, emails…" className="mb-4 max-w-[420px]" />

      <h4>Entities</h4>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Entity</TableHead><TableHead>Type</TableHead><TableHead>Confidence</TableHead>
            <TableHead>First seen</TableHead><TableHead>Last seen</TableHead><TableHead>Related</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {entities.map((e) => (
            <TableRow key={e.value}>
              <TableCell className="font-heading">{e.value}</TableCell>
              <TableCell><Badge variant="tag-neutral">{e.type}</Badge></TableCell>
              <TableCell>{e.confidence}%</TableCell>
              <TableCell className="text-muted-rk">{e.firstSeen}</TableCell>
              <TableCell className="text-muted-rk">{e.lastSeen}</TableCell>
              <TableCell className="text-muted-rk">{e.related} cases</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <h4 className="mt-6">Scam campaigns</h4>
      <div className="grid gap-3 md:grid-cols-3">
        {campaigns.map((c) => (
          <Link key={c.id} href={`/threat-intel/campaigns/${c.id}`}>
            <Card className="elev-sm cursor-pointer">
              <CardContent className="flex flex-col gap-1">
                <div className="text-[10px] font-extrabold tracking-[0.1em] text-primary uppercase">{c.confidence}% confidence</div>
                <div className="font-heading text-[17px] font-extrabold">{c.name}</div>
                <p className="text-[13px] opacity-80">{c.investigations} related investigations · {c.indicators} indicators</p>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      <h4 className="mt-6">Live scam feed</h4>
      <p className="text-[13px] text-muted-rk">Recently reported malicious URLs, via URLhaus (abuse.ch).</p>
      {feed.length === 0 ? (
        <p className="mt-2 text-[13px] text-muted-rk">No live feed data available right now.</p>
      ) : (
        <div className="mt-2 grid gap-2 md:grid-cols-2">
          {feed.map((item) => (
            <Card key={item.url}>
              <CardContent className="flex flex-col gap-1">
                <div className="flex items-center justify-between gap-2">
                  <Badge variant="tag-neutral">{item.threat}</Badge>
                  <span className="text-[11px] text-muted-rk">{item.date_added}</span>
                </div>
                <div className="truncate font-heading text-[13px] font-extrabold" title={item.url}>{item.host || item.url}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <h4 className="mt-6">How to stay safe</h4>
      <div className="grid gap-2 md:grid-cols-2">
        {SAFETY_TIPS.map((tip) => (
          <Card key={tip}>
            <CardContent className="text-[13px]">{tip}</CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
