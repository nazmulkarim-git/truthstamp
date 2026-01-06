import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "TruthStamp",
  description: "Digital evidence, verified. Provenance-first analysis for photos & videos.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-white text-slate-900 antialiased">
        {children}
      </body>
    </html>
  );
}
