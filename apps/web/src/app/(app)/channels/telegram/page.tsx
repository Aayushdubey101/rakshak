import { Badge } from "@/components/ui/badge";
import { ChannelConnectCard } from "@/components/channel-connect-card";
import { telegramBotUrl } from "@/lib/channel-links";

const FLOW = ["TELEGRAM", "FORWARD", "RAKSHAK BOT", "ANALYZE", "SHORT REPORT"];

export default function TelegramChannelPage() {
  const href = telegramBotUrl();
  return (
    <div data-screen-label="telegram" className="mx-auto max-w-[640px] px-4 py-10 md:px-6">
      <h6 className="text-[var(--rk-accent-700)]">Channels · Telegram</h6>
      <h2>Connect Rakshak to Telegram</h2>
      <p className="text-[14px] text-muted-rk">Forward suspicious messages directly to your Rakshak bot.</p>

      <div className="my-4 flex flex-wrap items-center gap-2 font-heading text-xs font-extrabold tracking-[0.03em]">
        {FLOW.map((step) => <Badge key={step} variant="tag-neutral">{step}</Badge>)}
        →<Badge variant="tag-accent">FULL WEB REPORT</Badge>
      </div>

      <ChannelConnectCard
        channel="Telegram"
        href={href}
        connectLabel="Open Telegram Bot"
        envVarName="NEXT_PUBLIC_TELEGRAM_BOT_USERNAME"
      />
    </div>
  );
}
