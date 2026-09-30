"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { cx } from "@/lib/cx";

/**
 * The masthead.
 *
 * A client component for one reason: `aria-current` depends on the path, and a
 * server component cannot read it. It holds no data and no state, so the
 * hydration cost is a pathname comparison.
 *
 * The three views are the three questions a reviewer asks in order -- what did
 * the rules flag, what outlived a leaver, and what did we actually ingest -- and
 * the current one is marked with a solid tab rather than a tint, because at a
 * glance a tint is indistinguishable from a hover.
 */

const LINKS = [
  { href: "/", label: "Review" },
  { href: "/forensics", label: "Forensics" },
  { href: "/data", label: "Data" },
] as const;

function isCurrent(pathname: string, href: string): boolean {
  if (href === "/") {
    // A dossier belongs to the review: it is one finding, opened. Marking the
    // masthead current on it keeps the reader oriented after they follow a row.
    return pathname === "/" || pathname.startsWith("/findings");
  }
  return pathname === href || pathname.startsWith(`${href}/`);
}

/**
 * A register page with its ruled margin -- the same device the finding rows
 * use, at 22 pixels. The mark is the layout, not a badge next to it.
 */
function RegisterMark() {
  return (
    <svg
      width="22"
      height="22"
      viewBox="0 0 24 24"
      aria-hidden="true"
      focusable="false"
      className="shrink-0"
    >
      <rect
        x="3.5"
        y="2.5"
        width="17"
        height="19"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <line x1="9" y1="2.5" x2="9" y2="21.5" stroke="currentColor" strokeWidth="1.4" />
      <line x1="12" y1="7.5" x2="17.5" y2="7.5" stroke="currentColor" strokeWidth="1.1" />
      <line x1="12" y1="11" x2="17.5" y2="11" stroke="currentColor" strokeWidth="1.1" />
      <line x1="12" y1="14.5" x2="15" y2="14.5" stroke="currentColor" strokeWidth="1.1" />
    </svg>
  );
}

export function Nav() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-10 border-b-2 border-ink bg-card">
      <div className="mx-auto flex max-w-5xl items-stretch gap-x-4 px-4 sm:px-6">
        <Link
          href="/"
          className="focus-ring flex items-center gap-2.5 py-3 text-ink"
        >
          <RegisterMark />
          <span className="font-display text-lg leading-none tracking-tight">
            AccessLens
          </span>
        </Link>

        <nav className="ml-auto flex items-stretch">
          {LINKS.map(({ href, label }) => {
            const current = isCurrent(pathname, href);
            return (
              <Link
                key={href}
                href={href}
                aria-current={current ? "page" : undefined}
                className={cx(
                  "focus-ring flex items-center px-3 font-mono text-[11px] tracking-[0.15em] uppercase transition-colors sm:px-4",
                  current
                    ? "bg-ink text-paper"
                    : "text-muted hover:bg-card-sunk hover:text-ink",
                )}
              >
                {label}
              </Link>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
