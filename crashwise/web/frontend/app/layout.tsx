import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "CrashWise — Control Plane",
  description: "Autonomous vulnerability discovery dashboard",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-background text-foreground min-h-screen">
        <nav className="border-b border-border px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-lg font-bold tracking-tight">CrashWise</span>
            <span className="text-xs text-muted-foreground border border-border px-2 py-0.5 rounded">
              v1.1.0
            </span>
          </div>
          <div className="flex items-center gap-4 text-sm text-muted-foreground">
            <a href="/" className="hover:text-foreground transition">Dashboard</a>
            <a href="/crashes" className="hover:text-foreground transition">Crashes</a>
          </div>
        </nav>
        <main className="p-6">{children}</main>
      </body>
    </html>
  );
}
