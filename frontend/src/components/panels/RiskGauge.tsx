import { Card, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import type { Snapshot } from "@/lib/api";
import { verdictTone } from "@/lib/utils";

interface Props {
  data: Snapshot | null;
}

const TONE_HEX = {
  allow: "#00a87e",
  monitor: "#ec7e00",
  block: "#e23b4a",
} as const;

export function RiskGauge({ data }: Props) {
  const score = Math.round(data?.avg_risk_score ?? 0);
  const pct = Math.min(100, Math.max(0, score));
  const tone = verdictTone(pct);
  const stroke = TONE_HEX[tone];

  const r = 64;
  const c = 2 * Math.PI * r;
  const offset = c - (pct / 100) * c;

  return (
    <Card className="flex flex-col items-center text-center">
      <div className="self-start mb-4">
        <CardTitle>Mean Risk</CardTitle>
      </div>
      <div className="relative">
        <svg width="170" height="170" viewBox="0 0 170 170">
          <circle
            cx="85"
            cy="85"
            r={r}
            stroke="rgba(255,255,255,0.08)"
            strokeWidth="14"
            fill="none"
          />
          <circle
            cx="85"
            cy="85"
            r={r}
            stroke={stroke}
            strokeWidth="14"
            strokeLinecap="round"
            fill="none"
            strokeDasharray={c}
            strokeDashoffset={offset}
            transform="rotate(-90 85 85)"
            style={{
              transition: "stroke-dashoffset 0.6s ease, stroke 0.4s ease",
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div
            className="text-mono-lg tracking-[-0.03em]"
            style={{ color: stroke, fontSize: 44 }}
          >
            {pct}
          </div>
          <div className="mt-1 text-eyebrow text-ink-onDarkDim">of 100</div>
        </div>
      </div>
      <div className="mt-5 grid grid-cols-3 gap-1.5 w-full">
        <Badge tone="allow" className="justify-center">0–44 allow</Badge>
        <Badge tone="monitor" className="justify-center">45–69 monitor</Badge>
        <Badge tone="block" className="justify-center">70+ block</Badge>
      </div>
    </Card>
  );
}
