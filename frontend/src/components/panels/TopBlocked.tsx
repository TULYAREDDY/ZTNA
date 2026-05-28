import { Ban } from "lucide-react";
import { Card, CardTitle } from "@/components/ui/Card";
import type { Snapshot } from "@/lib/api";

interface Props {
  data: Snapshot | null;
}

export function TopBlocked({ data }: Props) {
  const items = data?.top_blocked_ips ?? [];
  const max = items.reduce((m, x) => Math.max(m, x.count), 0) || 1;

  return (
    <Card>
      <div className="mb-4 flex items-start justify-between">
        <CardTitle>Top Blocked IPs</CardTitle>
        <Ban className="h-[18px] w-[18px] text-ink-onDarkDim" />
      </div>
      {items.length === 0 ? (
        <div className="py-6 text-center text-body text-ink-onDarkDim">
          No blocks yet.
        </div>
      ) : (
        <ul className="space-y-3">
          {items.map((it) => (
            <li key={it.ip}>
              <div className="flex items-center justify-between">
                <span className="text-mono-md text-ink-onDarkMute">
                  {it.ip}
                </span>
                <span className="text-mono-md text-ink-onDark">
                  {it.count}
                </span>
              </div>
              <div className="mt-1.5 h-1.5 rounded-pill bg-white/5 overflow-hidden">
                <div
                  className="h-full rounded-pill bg-verdict-block"
                  style={{ width: `${(it.count / max) * 100}%` }}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
