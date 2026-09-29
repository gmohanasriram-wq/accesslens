import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AccessLens",
  description:
    "Telemetry-informed access review: what access exists, what was actually used, and whether it is still live after someone left.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body className="bg-white text-slate-900 antialiased dark:bg-slate-950 dark:text-slate-100">
        {children}
      </body>
    </html>
  );
}
