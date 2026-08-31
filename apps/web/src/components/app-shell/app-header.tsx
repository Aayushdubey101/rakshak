"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { BrandMark } from "@/components/brand-mark";
import { UserMenu, useCurrentUser } from "@/components/app-shell/user-menu";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/analyze", label: "Analyze" },
  { href: "/investigations", label: "Investigations" },
  { href: "/threat-intel", label: "Intel" },
  { href: "/channels", label: "Channels" },
  { href: "/settings", label: "Settings" },
];

export function AppHeader() {
  const pathname = usePathname();
  const user = useCurrentUser();

  return (
    <div className="sticky top-0 z-20 hidden items-center gap-6 border-b-2 border-border bg-background px-6 py-3 md:flex">
      <BrandMark className="mr-auto" />
      {NAV_ITEMS.map((item) => {
        const active = pathname.startsWith(item.href);
        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "text-sm text-foreground hover:text-primary",
              active && "text-primary"
            )}
          >
            {item.label}
          </Link>
        );
      })}
      {user && <UserMenu user={user} />}
    </div>
  );
}
