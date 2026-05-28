import { KpiRow } from "@/components/panels/KpiRow";
import { LiveFeed } from "@/components/panels/LiveFeed";
import { DecisionsChart } from "@/components/panels/DecisionsChart";
import { RiskGauge } from "@/components/panels/RiskGauge";
import { AttackPanel } from "@/components/panels/AttackPanel";
import { TopBlocked } from "@/components/panels/TopBlocked";
import { useEventStream } from "@/hooks/useEventStream";
import { usePoll } from "@/hooks/usePoll";
import { api } from "@/lib/api";

const SNAPSHOT_POLL_MS = 2500;

export function Dashboard() {
  const { events, connected } = useEventStream();
  const { data: snapshot } = usePoll(api.snapshot, SNAPSHOT_POLL_MS);

  return (
    <div className="space-y-grid">
      <KpiRow data={snapshot} />

      <div className="grid grid-cols-12 gap-grid">
        <div className="col-span-12 xl:col-span-8 space-y-grid">
          <DecisionsChart data={snapshot} />
          <LiveFeed events={events} connected={connected} />
        </div>
        <div className="col-span-12 xl:col-span-4 space-y-grid">
          <RiskGauge data={snapshot} />
          <AttackPanel />
          <TopBlocked data={snapshot} />
        </div>
      </div>
    </div>
  );
}
