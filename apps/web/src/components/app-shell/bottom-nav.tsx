"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Home, Search, ClipboardList, ShieldCheck, Settings } from "lucide-react";
import { cn } from "@/lib/utils";

export const MOBILE_NAV_ITEMS = [
  { href: "/dashboard", label: "Home", icon: Home },
  { href: "/analyze", label: "Analyze", icon: Search },
  { href: "/investigations", label: "Cases", icon: ClipboardList },
  { href: "/threat-intel", label: "Intel", icon: ShieldCheck },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function BottomNav({ items = MOBILE_NAV_ITEMS }: { items?: typeof MOBILE_NAV_ITEMS }) {
  const pathname = usePathname();
  const onDashboard = pathname === "/dashboard";
  const resolved = items.map((item, i) =>
    i === 0
      ? onDashboard
        ? { ...item, href: "/", label: "Home" }
        : { ...item, href: "/dashboard", label: "Dashboard" }
      : item
  );

  return (
    <div className="fixed inset-x-0 bottom-0 z-30 flex border-t-2 border-border bg-background md:hidden">
      {resolved.map(({ href, label, icon: Icon }) => {
        const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
        return (
          <Link
            key={href}
            href={href}
            className={cn(
              "flex flex-1 flex-col items-center gap-0.5 py-2.5 text-[10px]",
              active ? "text-primary" : "text-[var(--rk-neutral-700)]"
            )}
          >
            <Icon className="size-5" strokeWidth={1.7} />
            {label}
          </Link>
        );
      })}
    </div>
  );
}
