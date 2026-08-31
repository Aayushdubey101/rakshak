import { Badge } from "@/components/ui/badge";
import { ChannelConnectCard } from "@/components/channel-connect-card";
import { whatsAppChatUrl } from "@/lib/channel-links";

const FLOW = ["WHATSAPP", "FORWARD", "RAKSHAK", "ANALYZE", "SHORT REPORT"];

export default function WhatsappChannelPage() {
  const href = whatsAppChatUrl();
  return (
    <div data-screen-label="whatsapp" className="mx-auto max-w-[640px] px-4 py-10 md:px-6">
      <h6 className="text-[var(--rk-accent-700)]">Channels · WhatsApp</h6>
      <h2>Connect Rakshak to WhatsApp</h2>
      <p className="text-[14px] text-muted-rk">Forward suspicious messages directly to Rakshak.</p>

      <div className="my-4 flex flex-wrap items-center gap-2 font-heading text-xs font-extrabold tracking-[0.03em]">
        {FLOW.map((step) => <Badge key={step} variant="tag-neutral">{step}</Badge>)}
        →<Badge variant="tag-accent">FULL WEB REPORT</Badge>
      </div>

      <ChannelConnectCard
        channel="WhatsApp"
        href={href}
        connectLabel="Open WhatsApp"
        envVarName="NEXT_PUBLIC_WHATSAPP_NUMBER"
      />

      <h4 className="mt-6">Example short report</h4>
      <div className="max-w-[340px] whitespace-pre-line bg-[var(--rk-neutral-900)] p-4 font-mono text-[13px] leading-relaxed text-[#f8f4f4]">
        {"🔴 RAKSHAK ALERT\n\nLIKELY SCAM\n\nRisk: 91/100\nSeverity: CRITICAL\n\n⚠ Suspicious domain\n⚠ Credential harvesting pattern\n⚠ Similar known campaign\n\nDO NOT CLICK THE LINK.\n\nView Full Report →"}
      </div>
    </div>
  );
}
