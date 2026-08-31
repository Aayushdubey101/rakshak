import type { Severity } from "@/lib/mock-data";
import type { badgeVariants } from "@/components/ui/badge";
import type { VariantProps } from "class-variance-authority";

type BadgeVariant = NonNullable<VariantProps<typeof badgeVariants>["variant"]>;

export function severityBadgeVariant(severity: Severity): BadgeVariant {
  if (severity === "CRITICAL" || severity === "HIGH") return "tag-accent";
  if (severity === "SUSPICIOUS") return "tag-accent-2";
  return "tag-neutral";
}

export function scoreColorClass(risk: number): string {
  if (risk >= 61) return "text-[var(--rk-accent-700)]";
  if (risk >= 41) return "text-[var(--rk-accent-2-800)]";
  return "text-[var(--rk-neutral-700)]";
}
