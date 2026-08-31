import Link from "next/link";
import { notFound } from "next/navigation";
import { campaigns } from "@/lib/mock-data";

const STATS_LABELS = [
  { key: "confidence", label: "confidence", suffix: "%" },
  { key: "investigations", label: "related investigations", suffix: "" },
  { key: "indicators", label: "indicators", suffix: "" },
  { key: "domains", label: "domains", suffix: "" },
  { key: "phones", label: "phone numbers", suffix: "" },
] as const;

export default async function CampaignDetailPage({ params }: PageProps<"/threat-intel/campaigns/[id]">) {
  const { id } = await params;
  const campaign = campaigns.find((c) => c.id === id);
  if (!campaign) notFound();

  return (
    <div data-screen-label="campaign-detail" className="mx-auto max-w-[820px] px-4 py-10 md:px-6">
      <Link href="/threat-intel" className="text-[13px] hover:text-primary">← All campaigns</Link>
      <h6 className="mt-3 text-[var(--rk-accent-700)]">Scam campaign</h6>
      <h1>{campaign.name}</h1>
      <div className="my-4 flex flex-wrap gap-4">
        {STATS_LABELS.map(({ key, label, suffix }) => (
          <div key={key}>
            <div className="font-heading text-[28px] font-extrabold">{campaign[key]}{suffix}</div>
            <div className="text-[12px] text-muted-rk">{label}</div>
          </div>
        ))}
      </div>
      <p className="max-w-[600px] text-sm">{campaign.desc}</p>
      <h4 className="mt-6">Common pattern</h4>
      <p className="text-[14px] text-muted-rk">{campaign.pattern}</p>
    </div>
  );
}
