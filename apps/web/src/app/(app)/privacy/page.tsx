import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export default function PrivacyPage() {
  return (
    <div data-screen-label="privacy" className="mx-auto max-w-[760px] px-4 py-10 md:px-6">
      <h6 className="text-[var(--rk-accent-700)]">Privacy Center</h6>
      <h1>Your data. Your control.</h1>
      <div className="mt-4 flex flex-col gap-2">
        <Card>
          <CardContent className="flex flex-row items-center justify-between">
            <div>
              <div className="font-heading text-sm font-extrabold">Data retention</div>
              <p className="m-0 text-[13px] opacity-80">Reports are kept for 90 days by default</p>
            </div>
            <Badge variant="tag-outline">Configure</Badge>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex flex-row items-center justify-between">
            <div>
              <div className="font-heading text-sm font-extrabold">Cloud analysis</div>
              <p className="m-0 text-[13px] opacity-80">Content is processed securely to produce a verdict</p>
            </div>
            <Badge variant="tag-accent">Enabled</Badge>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex flex-row items-center justify-between">
            <div>
              <div className="font-heading text-sm font-extrabold">Data export</div>
              <p className="m-0 text-[13px] opacity-80">Download all your investigations and reports</p>
            </div>
            <Button variant="outline">Export</Button>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex flex-row items-center justify-between">
            <div>
              <div className="font-heading text-sm font-extrabold">Delete my data</div>
              <p className="m-0 text-[13px] opacity-80">Permanently remove your account and history</p>
            </div>
            <Button variant="ghost">Delete</Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
