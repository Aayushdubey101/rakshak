import { InvestigationsTable } from "./investigations-table";

export default function InvestigationsPage() {
  return (
    <div data-screen-label="investigations" className="mx-auto max-w-[1080px] px-4 py-10 md:px-6">
      <h6 className="text-[var(--rk-accent-700)]">Investigations</h6>
      <h2>Investigation history</h2>
      <InvestigationsTable />
    </div>
  );
}
