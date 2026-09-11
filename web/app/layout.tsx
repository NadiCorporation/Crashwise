import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "CrashWise",
  description: "Fuzzing control plane",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-background text-foreground min-h-screen font-mono">
        <nav className="border-b border-border px-4 py-2 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold">⚡ CrashWise</span>
            <span className="text-[10px] text-muted-foreground border border-border px-1.5 py-0.5 rounded">
              v1.1.0
            </span>
          </div>
          <div className="text-[10px] text-muted-foreground">
            Control Plane
          </div>
        </nav>
        <main className="p-4">{children}</main>
      </body>
    </html>
  );
}
