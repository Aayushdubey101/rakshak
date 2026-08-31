"use client";

import { useRouter } from "next/navigation";
import type { ComponentProps, KeyboardEvent } from "react";
import { TableRow } from "@/components/ui/table";

interface ClickableTableRowProps extends ComponentProps<typeof TableRow> {
  href: string;
}

/** TableRow that navigates on click — <tr> can't render as an <a>, so this uses router.push instead. */
export function ClickableTableRow({ href, className, ...props }: ClickableTableRowProps) {
  const router = useRouter();

  function handleKeyDown(event: KeyboardEvent<HTMLTableRowElement>) {
    if (event.key === "Enter") router.push(href);
  }

  return (
    <TableRow
      role="link"
      tabIndex={0}
      onClick={() => router.push(href)}
      onKeyDown={handleKeyDown}
      className={`cursor-pointer ${className ?? ""}`}
      {...props}
    />
  );
}
