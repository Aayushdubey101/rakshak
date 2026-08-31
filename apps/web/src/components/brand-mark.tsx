import Link from "next/link";

interface BrandMarkProps {
  href?: string;
  className?: string;
}

export function BrandMark({ href = "/", className }: BrandMarkProps) {
  const content = (
    <span className="inline-flex items-center gap-2.5 font-heading text-lg font-extrabold">
      <span className="size-3.5 rotate-45 bg-primary" />
      RAKSHAK
    </span>
  );

  if (!href) return <span className={className}>{content}</span>;
  return <Link href={href} className={className}>{content}</Link>;
}
