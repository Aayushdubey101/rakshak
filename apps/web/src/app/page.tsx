"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { BrandMark } from "@/components/brand-mark";
import { IntelligenceCore } from "@/components/intelligence-core";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { UserMenu, useCurrentUser } from "@/components/app-shell/user-menu";
import { AuthDialog } from "@/components/auth/auth-dialog";
import { BottomNav, MOBILE_NAV_ITEMS } from "@/components/app-shell/bottom-nav";

const THREE_WAYS = [
  {
    kicker: "01 — Web",
    title: "Analyze suspicious content directly",
    body: "No connection required. Paste a message, link, or upload an image or document.",
    trail: "WEB → ANALYZE → FULL REPORT",
    cta: "Analyze Now →",
    href: "/analyze",
  },
  {
    kicker: "02 — WhatsApp",
    title: "Forward suspicious content directly",
    body: "Optional. Forward a message, image, or link to Rakshak on WhatsApp.",
    trail: "WHATSAPP → FORWARD → SHORT REPORT → FULL WEB REPORT",
    cta: "Connect WhatsApp →",
    href: "/channels/whatsapp",
  },
  {
    kicker: "03 — Telegram",
    title: "Forward suspicious content directly",
    body: "Optional. Forward a message, image, or link to your Rakshak bot.",
    trail: "TELEGRAM → FORWARD → SHORT REPORT → FULL WEB REPORT",
    cta: "Connect Telegram →",
    href: "/channels/telegram",
  },
];

const THINK_COLUMNS = [
  { kicker: "See Rakshak think", title: "Detect → Analyze → Correlate → Evaluate → Protect", body: "Every submission moves through machine-learning classifiers, cybersecurity checks, and threat-intelligence correlation before a verdict is reached." },
  { kicker: "AI + ML + Cybersecurity", title: "Multi-model reasoning", body: "Multi-LLM reasoning, ML risk models, and domain/URL/entity analysis run together, then fuse into one risk score with a confidence level." },
  { kicker: "Threat Intelligence", title: "Campaign correlation", body: "Domains, phone numbers, UPI IDs, and emails are checked against known scam campaigns and prior investigations." },
];

export default function LandingPage() {
  const user = useCurrentUser();
  const [authOpen, setAuthOpen] = useState(false);
  const [authTab, setAuthTab] = useState<"login" | "register">("login");

  useEffect(() => {
    if (new URLSearchParams(window.location.search).get("auth") === "login") {
      setAuthTab("login");
      setAuthOpen(true);
    }
  }, []);

  function openAuth(tab: "login" | "register") {
    setAuthTab(tab);
    setAuthOpen(true);
  }

  return (
    <div data-screen-label="landing" className="pb-16 md:pb-0">
      <AuthDialog open={authOpen} onOpenChange={setAuthOpen} defaultTab={authTab} />
      <BottomNav items={MOBILE_NAV_ITEMS.slice(0, 3)} />
      <div className="sticky top-0 z-20 flex flex-wrap items-center gap-3 border-b-2 border-border bg-background px-4 py-3 md:gap-6 md:px-6">
        <BrandMark className="mr-auto" />
        {user ? (
          <>
            <Link href="/dashboard" className="text-sm hover:text-primary">Dashboard</Link>
            <UserMenu user={user} />
          </>
        ) : (
          <>
            <Button variant="link" className="h-auto p-0 text-sm font-normal text-foreground hover:text-primary hover:no-underline" onClick={() => openAuth("login")}>Log in</Button>
            <Button variant="outline" size="sm" className="md:h-8 md:text-sm" onClick={() => openAuth("register")}>Create account</Button>
          </>
        )}
        <Button size="sm" className="md:h-8 md:text-sm" render={<Link href="/analyze" />}>Analyze on Web</Button>
      </div>

      <div className="mx-auto grid max-w-[1180px] items-center gap-8 px-4 py-16 md:grid-cols-[1.1fr_0.9fr] md:px-6">
        <div>
          <div className="mb-3 text-xs font-extrabold tracking-[0.14em] text-[var(--rk-accent-700)]">
            DIGITAL SAFETY INTELLIGENCE
          </div>
          <h1 className="text-[38px] text-pretty md:text-[56px]">DON&apos;T TRUST IT. CHECK IT.</h1>
          <p className="max-w-[520px] text-[17px] opacity-85">
            AI + ML powered cybersecurity intelligence for the suspicious content you receive every day.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <Button render={<Link href="/analyze" />}>Analyze on Web</Button>
            <Button variant="outline" render={<Link href="/channels/whatsapp" />}>Connect WhatsApp</Button>
            <Button variant="outline" render={<Link href="/channels/telegram" />}>Connect Telegram</Button>
          </div>
        </div>
        <div className="flex justify-center">
          <IntelligenceCore size={240} className="md:hidden" />
          <IntelligenceCore size={320} className="hidden md:block" />
        </div>
      </div>

      <Separator className="mx-auto max-w-[1180px]" />

      <div className="mx-auto max-w-[1180px] px-6 py-16">
        <h6 className="text-[var(--rk-accent-700)]">Three ways to use Rakshak</h6>
        <div className="mt-3 grid gap-4 md:grid-cols-3">
          {THREE_WAYS.map((way) => (
            <Card key={way.kicker} className="elev-sm gap-2" size="sm">
              <CardContent className="flex flex-1 flex-col gap-2">
                <div className="text-[10px] font-extrabold tracking-[0.1em] text-primary uppercase">{way.kicker}</div>
                <div className="font-heading text-[17px] font-extrabold">{way.title}</div>
                <p className="flex-1 text-[13px] opacity-80">{way.body}</p>
                <div className="font-heading text-[11px] tracking-[0.04em] opacity-60">{way.trail}</div>
                <Button variant="ghost" className="justify-start px-0 text-primary hover:text-primary" render={<Link href={way.href} />}>
                  {way.cta}
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      <Separator className="mx-auto max-w-[1180px]" />

      <div className="mx-auto grid max-w-[1180px] gap-6 px-6 py-16 md:grid-cols-3">
        {THINK_COLUMNS.map((col) => (
          <div key={col.kicker}>
            <h6 className="text-[var(--rk-accent-700)]">{col.kicker}</h6>
            <h3>{col.title}</h3>
            <p className="text-[14px] text-muted-rk">{col.body}</p>
          </div>
        ))}
      </div>

      <Separator className="mx-auto max-w-[1180px]" />

      <div className="mx-auto grid max-w-[1180px] items-center gap-6 px-6 py-16 md:grid-cols-[1.1fr_0.9fr]">
        <div>
          <h6 className="text-[var(--rk-accent-700)]">Privacy</h6>
          <h2>Your data. Your control.</h2>
          <p className="max-w-[480px] text-[14px] text-muted-rk">
            Content is processed securely to produce a verdict, retained only as long as needed, and can be exported or deleted at any time.
          </p>
          <Button variant="outline" className="mt-2" render={<Link href="/privacy" />}>Privacy Center →</Button>
        </div>
        <Card className="elev-md">
          <CardContent className="flex flex-col gap-2 text-[13px]">
            <div className="text-[10px] font-extrabold tracking-[0.1em] text-primary uppercase">Data handling</div>
            <div>— Secure processing, no public exposure of submitted content</div>
            <div>— Configurable retention and one-click deletion</div>
            <div>— Full data export on request</div>
          </CardContent>
        </Card>
      </div>

      <div className="bg-[var(--rk-accent-900)] px-6 py-16 text-[#f8f4f4]">
        <div className="mx-auto flex max-w-[1180px] flex-wrap items-center justify-between gap-4">
          <h2 className="text-[#f8f4f4]">Check it before you trust it.</h2>
          <div className="flex flex-wrap gap-2">
            <Button render={<Link href="/analyze" />}>Analyze on Web</Button>
            <Button variant="outline" className="border-[#f8f4f4] bg-transparent text-[#f8f4f4] hover:bg-white/10 hover:text-[#f8f4f4]" onClick={() => openAuth("register")}>
              Create free account
            </Button>
          </div>
        </div>
      </div>

      <div className="mx-auto flex max-w-[1180px] flex-wrap items-center justify-between gap-3 px-6 py-6 text-xs text-muted-rk">
        <div>© Rakshak Security Intelligence</div>
        <div className="flex gap-4">
          <Link href="/privacy" className="hover:text-primary">Privacy</Link>
          <Link href="/threat-intel" className="hover:text-primary">Threat Intelligence</Link>
          <Button variant="link" className="h-auto p-0 text-xs font-normal text-muted-rk hover:text-primary hover:no-underline" onClick={() => openAuth("login")}>Log in</Button>
        </div>
      </div>
    </div>
  );
}
