import { CampaignsTable } from "@/components/campaigns-table";
import { LiveTelemetry } from "@/components/telemetry";

export default function DashboardPage() {
  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Real-time autonomous fuzzing operations
        </p>
      </header>

      <LiveTelemetry />

      <section>
        <h2 className="text-lg font-semibold mb-4 border-b border-border pb-2">
          Active Campaigns
        </h2>
        <CampaignsTable />
      </section>
    </div>
  );
}
