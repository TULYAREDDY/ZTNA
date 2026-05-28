import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardSubtitle, CardTitle } from "@/components/ui/Card";
import type { Snapshot } from "@/lib/api";

interface Props {
  data: Snapshot | null;
}

const COLOR = {
  allow: "#00a87e",
  monitor: "#ec7e00",
  block: "#e23b4a",
} as const;

export function DecisionsChart({ data }: Props) {
  const points = (data?.decision_timeline ?? []).map((p) => ({
    ts: new Date(p.ts).toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }),
    ALLOW: p.ALLOW,
    MONITOR: p.MONITOR,
    BLOCK: p.BLOCK,
  }));

  return (
    <Card className="flex flex-col h-[280px]">
      <div>
        <CardTitle>Decisions over time</CardTitle>
        <CardSubtitle>10-second buckets</CardSubtitle>
      </div>

      {points.length === 0 ? (
        <div className="flex flex-1 items-center justify-center text-caption text-ink-onDarkDim">
          No traffic yet.
        </div>
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={points}
            margin={{ top: 16, right: 8, left: -22, bottom: 0 }}
          >
            <defs>
              <linearGradient id="gAllow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={COLOR.allow} stopOpacity={0.45} />
                <stop offset="100%" stopColor={COLOR.allow} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gMonitor" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={COLOR.monitor} stopOpacity={0.45} />
                <stop offset="100%" stopColor={COLOR.monitor} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gBlock" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={COLOR.block} stopOpacity={0.5} />
                <stop offset="100%" stopColor={COLOR.block} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
            <XAxis
              dataKey="ts"
              stroke="rgba(255,255,255,0.28)"
              tick={{ fill: "rgba(255,255,255,0.48)", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              minTickGap={40}
            />
            <YAxis
              stroke="rgba(255,255,255,0.28)"
              tick={{ fill: "rgba(255,255,255,0.48)", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
            />
            <Tooltip
              cursor={{ fill: "rgba(255,255,255,0.04)" }}
              contentStyle={{
                background: "#16181a",
                border: "1px solid rgba(255,255,255,0.10)",
                borderRadius: 12,
                fontSize: 12,
                fontFamily: "Inter, system-ui, sans-serif",
                color: "#ffffff",
              }}
              labelStyle={{ color: "rgba(255,255,255,0.48)" }}
            />
            <Area
              type="monotone"
              dataKey="ALLOW"
              stackId="1"
              stroke={COLOR.allow}
              fill="url(#gAllow)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="MONITOR"
              stackId="1"
              stroke={COLOR.monitor}
              fill="url(#gMonitor)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="BLOCK"
              stackId="1"
              stroke={COLOR.block}
              fill="url(#gBlock)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </Card>
  );
}
