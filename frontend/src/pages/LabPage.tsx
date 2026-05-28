import { AttackPanel } from "@/components/panels/AttackPanel";
import { LiveFeed } from "@/components/panels/LiveFeed";
import { useEventStream } from "@/hooks/useEventStream";

export function LabPage() {
  const { events, connected } = useEventStream();
  return (
    <div className="grid grid-cols-12 gap-grid">
      <div className="col-span-12 xl:col-span-4">
        <AttackPanel />
      </div>
      <div className="col-span-12 xl:col-span-8">
        <LiveFeed events={events} connected={connected} />
      </div>
    </div>
  );
}
