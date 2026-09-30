import type { Metadata } from "next";

import { DatasetStrip } from "@/components/DatasetStrip";
import { Nav } from "@/components/Nav";

import "./globals.css";

export const metadata: Metadata = {
  title: "AccessLens — access review and deprovisioning forensics",
  description:
    "Telemetry-informed access review. Findings are produced by deterministic rules, and every access change is approved by a person.",
};

/**
 * The shell: masthead, the page, the provenance line.
 *
 * There is exactly one `<main>` per page and the pages do not supply it, so
 * "which part of this is the document" is answered once, here. The same is true
 * of the dataset strip -- every view states the window and the dataset it was
 * computed from, and a page that forgot to would be a page whose findings have
 * no provenance.
 *
 * The layout is a flex column with the document growing, so a short page (a
 * dossier with one exhibit) still puts the provenance at the foot of the
 * viewport rather than halfway up it.
 */
export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body className="flex min-h-screen flex-col bg-paper text-ink antialiased">
        <Nav />
        <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-8 sm:px-6 sm:py-10">
          {children}
        </main>
        <DatasetStrip />
      </body>
    </html>
  );
}
