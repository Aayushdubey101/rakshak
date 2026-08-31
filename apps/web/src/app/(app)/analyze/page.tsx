import { AnalyzeForm } from "./analyze-form";

export default function AnalyzePage() {
  return (
    <div data-screen-label="analyze" className="mx-auto max-w-[1080px] px-4 py-10 md:px-6">
      <h6 className="text-[var(--rk-accent-700)]">Analyze</h6>
      <h2>What should Rakshak check?</h2>
      <p className="max-w-[520px] text-[14px] text-muted-rk">
        Paste a message, drop a screenshot, check a link, or upload a document — Rakshak runs the same investigation on all four.
      </p>
      <div className="mt-4">
        <AnalyzeForm />
      </div>
    </div>
  );
}
