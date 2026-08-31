import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export default function ChannelsPage() {
  return (
    <div data-screen-label="channels" className="mx-auto max-w-[900px] px-4 py-10 md:px-6">
      <h6 className="text-[var(--rk-accent-700)]">Channels</h6>
      <h2>Connected channels</h2>
      <p className="max-w-[560px] text-[14px] text-muted-rk">
        Web works on its own. WhatsApp and Telegram are optional convenience channels for forwarding suspicious content.
      </p>

      <div className="mt-4 flex flex-col gap-3">
        <Card className="elev-sm">
          <CardContent className="flex flex-row items-center justify-between">
            <div>
              <div className="font-heading text-[15px] font-extrabold">Web</div>
              <p className="m-0 text-[13px] opacity-80">Analyze directly from Rakshak.</p>
            </div>
            <Badge variant="tag-accent">Active</Badge>
          </CardContent>
        </Card>

        <Card className="elev-sm">
          <CardContent className="flex flex-row flex-wrap items-center justify-between gap-2">
            <div>
              <div className="font-heading text-[15px] font-extrabold">WhatsApp</div>
              <p className="m-0 text-[13px] opacity-80">Not connected</p>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" render={<Link href="/channels/whatsapp" />}>Manage</Button>
              <Button render={<Link href="/channels/whatsapp" />}>Connect</Button>
            </div>
          </CardContent>
        </Card>

        <Card className="elev-sm">
          <CardContent className="flex flex-row flex-wrap items-center justify-between gap-2">
            <div>
              <div className="font-heading text-[15px] font-extrabold">Telegram</div>
              <p className="m-0 text-[13px] opacity-80">Not connected</p>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" render={<Link href="/channels/telegram" />}>Manage</Button>
              <Button render={<Link href="/channels/telegram" />}>Connect</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
