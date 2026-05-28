import { Activity, Ban, Gauge, Users } from "lucide-react";
import { Card } from "@/components/ui/Card";
import type { Snapshot } from "@/lib/api";
import { cn, riskTextClass } from "@/lib/utils";

interface Props {
  data: Snapshot | null;
}

interface Tile {
  label: string;
  value: string;
  icon: typeof Activity;
  /** Optional Tailwind class to tint the value (only when semantically meaningful). */
  valueClass?: string;
}

export function KpiRow({ data }: Props) {
  const blockRate = data?.block_rate ?? 0;

  const tiles: Tile[] = [
    {
      label: "Active Sessions",
      value: String(data?.active_sessions ?? 0),
      icon: Users,
    },
    {
      label: "Decisions / min",
      value: String(data?.decisions_per_minute ?? 0),
      icon: Activity,
    },
    {
      label: "Avg Risk",
      value: data ? data.avg_risk_score.toFixed(1) : "0.0",
      icon: Gauge,
      valueClass: data ? riskTextClass(data.avg_risk_score) : undefined,
    },
    {
      label: "Block Rate",
      value: data ? `${(blockRate * 100).toFixed(1)}%` : "0%",
      icon: Ban,
      valueClass: blockRate > 0.05 ? "text-verdict-block" : undefined,
    },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-grid">
      {tiles.map((t) => (
        <Card key={t.label}>
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="text-eyebrow text-ink-onDarkDim">{t.label}</div>
              <div
                className={cn(
                  "mt-3 text-mono-lg",
                  t.valueClass ?? "text-ink-onDark",
                )}
              >
                {t.value}
              </div>
            </div>
            <t.icon className="h-[18px] w-[18px] shrink-0 text-ink-onDarkDim" />
          </div>
        </Card>
      ))}
    </div>
  );
}
