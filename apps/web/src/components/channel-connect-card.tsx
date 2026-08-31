import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

interface ChannelConnectCardProps {
  channel: "WhatsApp" | "Telegram";
  href: string | null;
  connectLabel: string;
  envVarName: string;
}

/** Opens a real chat with the bot — no fake "connecting" simulation, since there's no backend yet to confirm a real connection. */
export function ChannelConnectCard({ channel, href, connectLabel, envVarName }: ChannelConnectCardProps) {
  return (
    <Card className="elev-sm">
      <CardContent className="flex flex-col gap-2">
        <div className="text-[10px] font-extrabold tracking-[0.1em] text-primary uppercase">Status</div>
        {href ? (
          <>
            <div className="font-heading text-[17px] font-extrabold">Ready to connect</div>
            <p className="text-[13px] opacity-80">
              Opens a chat with the Rakshak {channel} bot. Forward anything suspicious there to get a short report.
            </p>
            <Button
              className="w-full justify-center"
              nativeButton={false}
              render={<a href={href} target="_blank" rel="noopener noreferrer" />}
            >
              {connectLabel}
            </Button>
          </>
        ) : (
          <>
            <div className="flex items-center gap-2">
              <span className="font-heading text-[17px] font-extrabold">Not yet available</span>
              <Badge variant="tag-neutral">Not configured</Badge>
            </div>
            <p className="text-[13px] opacity-80">
              The {channel} bot isn&apos;t deployed yet. Set <code className="font-mono">{envVarName}</code> once it is.
            </p>
            <Button className="w-full justify-center" disabled>{connectLabel}</Button>
          </>
        )}
      </CardContent>
    </Card>
  );
}
