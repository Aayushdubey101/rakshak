import Link from "next/link";
import { IntelligenceCore } from "@/components/intelligence-core";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

const OPTIONS = [
  { title: "Analyze on Web", body: "Works immediately, no setup." },
  { title: "Connect WhatsApp", body: "Forward messages for a quick check." },
  { title: "Connect Telegram", body: "Forward to your Rakshak bot." },
];

export default function OnboardingPage() {
  return (
    <div
      data-screen-label="onboarding"
      className="flex min-h-screen flex-col items-center justify-center gap-4 p-6 text-center"
    >
      <IntelligenceCore size={180} />
      <h1 className="mt-4">Welcome to Rakshak</h1>
      <p className="max-w-[440px] text-[15px] text-muted-rk">Your personal digital security layer.</p>
      <div className="mt-6 grid w-full max-w-[760px] gap-3 text-left md:grid-cols-3">
        {OPTIONS.map((opt) => (
          <Card key={opt.title}>
            <CardContent className="flex flex-col gap-1">
              <div className="font-heading text-[15px] font-extrabold">{opt.title}</div>
              <p className="text-[13px] opacity-80">{opt.body}</p>
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="mt-6 flex flex-wrap justify-center gap-2">
        <Button render={<Link href="/analyze" />}>Start analyzing</Button>
        <Button variant="outline" render={<Link href="/channels/whatsapp" />}>Connect WhatsApp</Button>
        <Button variant="outline" render={<Link href="/channels/telegram" />}>Connect Telegram</Button>
        <Button variant="ghost" className="text-primary hover:text-primary" render={<Link href="/dashboard" />}>
          Skip for now
        </Button>
      </div>
    </div>
  );
}
