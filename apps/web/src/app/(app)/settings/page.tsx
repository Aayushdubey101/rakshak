"use client";

import Link from "next/link";
import { useEffect, useState, type ReactNode } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { getCurrentUser, type CurrentUser } from "@/lib/api";

export default function SettingsPage() {
  const [user, setUser] = useState<CurrentUser | null>(null);

  useEffect(() => {
    setUser(getCurrentUser());
  }, []);

  // Only rows backed by a real page/endpoint -- Security, Notifications, and
  // Analysis preferences had no backend behind them (clicking did nothing),
  // which is what made this page feel broken. Removed until there's
  // something real for them to open.
  const ROWS: { title: string; meta: ReactNode }[] = [
    { title: "Account", meta: user?.email ?? "Not signed in" },
    { title: "Privacy", meta: <Link href="/privacy" className="hover:text-primary">Open Privacy Center →</Link> },
    { title: "Connected channels", meta: <Link href="/channels" className="hover:text-primary">Manage →</Link> },
  ];

  return (
    <div data-screen-label="settings" className="mx-auto max-w-[760px] px-4 py-10 md:px-6">
      <h6 className="text-[var(--rk-accent-700)]">Settings</h6>
      <h2>Account & security</h2>
      <div className="mt-4 flex flex-col gap-2">
        {ROWS.map((row) => (
          <Card key={row.title}>
            <CardContent className="flex flex-row items-center justify-between">
              <span className="font-heading text-sm font-extrabold">{row.title}</span>
              <span className="text-[13px] text-muted-rk">{row.meta}</span>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
