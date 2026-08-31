"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { IntelligenceCore } from "@/components/intelligence-core";
import { investigationStages } from "@/lib/mock-data";

const STAGE_INTERVAL_MS = 550;
const REDIRECT_DELAY_MS = 500;

export default function InvestigatingPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const investigationId = searchParams.get("id");
  const [stage, setStage] = useState(0);

  useEffect(() => {
    if (!investigationId) {
      router.replace("/analyze");
      return;
    }
    const timer = setInterval(() => {
      setStage((current) => {
        const next = current + 1;
        if (next >= investigationStages.length) {
          clearInterval(timer);
          setTimeout(() => router.replace(`/reports/${investigationId}`), REDIRECT_DELAY_MS);
        }
        return Math.min(next, investigationStages.length - 1);
      });
    }, STAGE_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [router, investigationId]);

  return (
    <div data-screen-label="investigating" className="mx-auto max-w-[640px] px-4 py-10 text-center md:px-6">
      <div className="flex justify-center"><IntelligenceCore size={240} /></div>
      <h6 className="mt-4 text-[var(--rk-accent-700)]">Investigation mode</h6>
      <h2>Rakshak is checking this now</h2>
      <div className="mt-4 flex flex-col text-left">
        {investigationStages.map((name, i) => {
          const done = i < stage;
          const active = i === stage;
          return (
            <div key={name} className="flex items-center gap-3 border-b border-border py-2.5">
              {done && (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" strokeWidth={2} className="flex-none">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
              )}
              {active && (
                <span
                  className="size-[18px] flex-none rounded-full border-2 border-primary"
                  style={{ borderTopColor: "transparent", animation: "rk-spin .8s linear infinite" }}
                />
              )}
              {!done && !active && <span className="size-[18px] flex-none rounded-full border-2 border-border" />}
              <span className={`text-sm ${done || active ? "text-foreground" : "text-foreground/45"}`}>{name}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
