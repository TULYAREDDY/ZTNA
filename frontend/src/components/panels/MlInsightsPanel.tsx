import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardSubtitle, CardTitle } from "@/components/ui/Card";
import type { MlMetrics, ModelComparisonRow } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Props {
  data: MlMetrics | null;
}

const COLOR = {
  brand: "#494fdf",
  brandDim: "rgba(73, 79, 223, 0.45)",
  allow: "#00a87e",
  monitor: "#ec7e00",
  block: "#e23b4a",
  axis: "rgba(255,255,255,0.28)",
  tick: "rgba(255,255,255,0.48)",
  grid: "rgba(255,255,255,0.06)",
} as const;

const TOOLTIP_STYLE = {
  background: "#16181a",
  border: "1px solid rgba(255,255,255,0.10)",
  borderRadius: 12,
  fontSize: 12,
  fontFamily: "Inter, system-ui, sans-serif",
  color: "#ffffff",
};

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: string;
}) {
  return (
    <div className="rounded-input bg-canvas-dark p-3">
      <div className="text-eyebrow text-ink-onDarkDim">{label}</div>
      <div
        className={cn("mt-2 text-mono-lg", tone ?? "text-ink-onDark")}
        style={{ fontSize: 24 }}
      >
        {value}
      </div>
    </div>
  );
}

function pct(v?: number, digits = 1) {
  if (v == null) return "—";
  return `${(v * 100).toFixed(digits)}%`;
}

function num(v?: number, digits = 3) {
  if (v == null) return "—";
  return v.toFixed(digits);
}

export function MlInsightsPanel({ data }: Props) {
  if (!data || !data.trained) {
    return (
      <Card>
        <CardTitle>ML Insights</CardTitle>
        <CardSubtitle>Run training to populate this panel</CardSubtitle>
        <div className="mt-4 rounded-input bg-canvas-dark p-4 text-body text-ink-onDarkMute">
          The classifier is not loaded yet. The backend auto-trains on
          startup, or you can run manually from the project root:
          <pre className="mt-2 rounded-input bg-surface-deep p-3 text-mono-md text-ink-onDarkMute">
{`make train
# or
cd backend && python -m app.ml.train`}
          </pre>
          Until training completes, access decisions use the rule engine only.
        </div>
      </Card>
    );
  }

  const fi = data.feature_importance ?? [];
  const cm = data.confusion_matrix ?? [
    [0, 0],
    [0, 0],
  ];
  const roc = data.roc_curve ?? [];
  const pr = data.pr_curve ?? [];
  const cal = data.calibration_curve ?? [];
  const comparison = data.model_comparison ?? [];
  const meta = data.metadata;
  const chosen = data.chosen_model;

  // Confusion matrix tones: TN green-ish, FP monitor, FN block, TP neutral.
  const cmCells = [
    { label: "TN", value: cm[0][0], tone: "text-verdict-allow" },
    { label: "FP", value: cm[0][1], tone: "text-verdict-monitor" },
    { label: "FN", value: cm[1][0], tone: "text-verdict-block" },
    { label: "TP", value: cm[1][1], tone: "text-ink-onDark" },
  ];

  const accuracyTone =
    (data.accuracy ?? 0) >= 0.9 ? "text-verdict-allow" : "text-ink-onDark";

  return (
    <div className="grid gap-grid lg:grid-cols-3">
      <Card className="lg:col-span-3">
        <CardTitle>Model Performance</CardTitle>
        <CardSubtitle>{data.model}</CardSubtitle>
        <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <Stat
            label="Accuracy"
            value={pct(data.accuracy)}
            tone={accuracyTone}
          />
          <Stat label="Precision" value={pct(data.precision)} />
          <Stat label="Recall" value={pct(data.recall)} />
          <Stat label="F1" value={num(data.f1)} />
          <Stat label="ROC-AUC" value={num(data.roc_auc)} />
          <Stat label="PR-AUC" value={num(data.pr_auc)} />
        </div>
        {meta && (
          <div className="mt-4 flex flex-wrap gap-x-5 gap-y-1 text-caption text-ink-onDarkDim">
            <span>
              trained{" "}
              <span className="text-ink-onDarkMute">
                {new Date(meta.trained_at).toLocaleString()}
              </span>
            </span>
            <span>
              dataset{" "}
              <span className="text-mono-md text-ink-onDarkMute">
                {meta.dataset_hash}
              </span>
            </span>
            <span>
              {meta.samples.toLocaleString()} rows · attack rate{" "}
              <span className="text-ink-onDarkMute">
                {pct(meta.attack_rate)}
              </span>
            </span>
            <span>
              sklearn{" "}
              <span className="text-ink-onDarkMute">
                {meta.sklearn_version}
              </span>
            </span>
            <span>
              {meta.cv_folds}-fold CV · seed {meta.seed}
            </span>
          </div>
        )}
      </Card>

      {comparison.length > 0 && (
        <Card className="lg:col-span-2">
          <CardTitle>Model Comparison</CardTitle>
          <CardSubtitle>5-fold stratified CV on the training split</CardSubtitle>
          <table className="mt-4 w-full">
            <thead>
              <tr className="text-left">
                {["Model", "F1 (mean ± std)", "ROC-AUC", "PR-AUC"].map((h) => (
                  <th
                    key={h}
                    className="px-2 py-2 text-eyebrow text-ink-onDarkDim font-normal"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {comparison.map((row: ModelComparisonRow) => {
                const isChosen = chosen && row.name === chosen.name;
                return (
                  <tr
                    key={row.name}
                    className="border-t border-hairline-soft"
                  >
                    <td className="px-2 py-2.5 text-body-strong text-ink-onDark">
                      {row.name.replace(/_/g, " ")}
                      {isChosen && (
                        <span className="ml-2 text-eyebrow text-brand-bright">
                          chosen
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-2.5 text-mono-md text-ink-onDark">
                      {row.cv_f1_mean.toFixed(4)}{" "}
                      <span className="text-ink-onDarkDim">
                        ± {row.cv_f1_std.toFixed(4)}
                      </span>
                    </td>
                    <td className="px-2 py-2.5 text-mono-md text-ink-onDarkMute">
                      {row.cv_roc_auc.toFixed(4)}
                    </td>
                    <td className="px-2 py-2.5 text-mono-md text-ink-onDarkMute">
                      {row.cv_pr_auc.toFixed(4)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {chosen && (
            <div className="mt-4 rounded-input bg-canvas-dark p-3 text-caption text-ink-onDarkDim">
              <span className="text-ink-onDarkMute">tuned params</span>{" "}
              <code className="text-mono-md text-ink-onDarkMute">
                {Object.entries(chosen.best_params)
                  .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
                  .join(", ")}
              </code>
              <span className="ml-3 text-ink-onDarkMute">calibration</span>{" "}
              <span className="text-ink-onDarkMute">{chosen.calibration}</span>
            </div>
          )}
        </Card>
      )}

      <Card>
        <CardTitle>Confusion Matrix</CardTitle>
        <CardSubtitle>
          {data.test_samples} test samples · τ ={" "}
          {num(data.optimal_threshold, 3)}
        </CardSubtitle>
        <div className="mt-4 grid grid-cols-2 gap-2 max-w-xs mx-auto">
          {cmCells.map((c) => (
            <div
              key={c.label}
              className="aspect-square flex flex-col items-center justify-center rounded-input bg-canvas-dark"
            >
              <div
                className={cn("text-mono-lg", c.tone)}
                style={{ fontSize: 32 }}
              >
                {c.value}
              </div>
              <div className="mt-1 text-eyebrow text-ink-onDarkDim">
                {c.label}
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card className="lg:col-span-3">
        <CardTitle>Feature Importance</CardTitle>
        <CardSubtitle>
          Permutation importance — Δ F1 when each feature is shuffled
        </CardSubtitle>
        <div className="mt-3 h-[300px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={fi}
              layout="vertical"
              margin={{ top: 0, right: 12, left: 24, bottom: 0 }}
            >
              <CartesianGrid stroke={COLOR.grid} horizontal={false} />
              <XAxis
                type="number"
                stroke={COLOR.axis}
                tick={{ fill: COLOR.tick, fontSize: 10 }}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                type="category"
                dataKey="feature"
                stroke={COLOR.axis}
                tick={{ fill: "rgba(255,255,255,0.72)", fontSize: 11 }}
                tickLine={false}
                axisLine={false}
                width={130}
              />
              <Tooltip
                cursor={{ fill: "rgba(255,255,255,0.04)" }}
                contentStyle={TOOLTIP_STYLE}
                labelStyle={{ color: "rgba(255,255,255,0.48)" }}
                formatter={(v: number) => v.toFixed(4)}
              />
              <Bar dataKey="importance" fill={COLOR.brand} radius={[0, 6, 6, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <Card className="lg:col-span-1">
        <CardTitle>ROC Curve</CardTitle>
        <CardSubtitle>AUC = {num(data.roc_auc)}</CardSubtitle>
        <div className="mt-3 h-[240px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={roc}
              margin={{ top: 10, right: 12, left: -10, bottom: 0 }}
            >
              <CartesianGrid stroke={COLOR.grid} />
              <XAxis
                dataKey="fpr"
                stroke={COLOR.axis}
                tick={{ fill: COLOR.tick, fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                domain={[0, 1]}
                type="number"
              />
              <YAxis
                stroke={COLOR.axis}
                tick={{ fill: COLOR.tick, fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                domain={[0, 1]}
              />
              <Tooltip cursor={false} contentStyle={TOOLTIP_STYLE} />
              <Line
                type="monotone"
                dataKey="tpr"
                stroke={COLOR.brand}
                strokeWidth={2.5}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <Card className="lg:col-span-1">
        <CardTitle>Precision–Recall</CardTitle>
        <CardSubtitle>AP = {num(data.pr_auc)}</CardSubtitle>
        <div className="mt-3 h-[240px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={pr}
              margin={{ top: 10, right: 12, left: -10, bottom: 0 }}
            >
              <CartesianGrid stroke={COLOR.grid} />
              <XAxis
                dataKey="recall"
                stroke={COLOR.axis}
                tick={{ fill: COLOR.tick, fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                domain={[0, 1]}
                type="number"
              />
              <YAxis
                stroke={COLOR.axis}
                tick={{ fill: COLOR.tick, fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                domain={[0, 1]}
              />
              <Tooltip cursor={false} contentStyle={TOOLTIP_STYLE} />
              <Line
                type="monotone"
                dataKey="precision"
                stroke={COLOR.brand}
                strokeWidth={2.5}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <Card className="lg:col-span-1">
        <CardTitle>Calibration</CardTitle>
        <CardSubtitle>Brier = {num(data.brier, 4)}</CardSubtitle>
        <div className="mt-3 h-[240px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={cal}
              margin={{ top: 10, right: 12, left: -10, bottom: 0 }}
            >
              <CartesianGrid stroke={COLOR.grid} />
              <XAxis
                dataKey="predicted"
                stroke={COLOR.axis}
                tick={{ fill: COLOR.tick, fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                domain={[0, 1]}
                type="number"
              />
              <YAxis
                stroke={COLOR.axis}
                tick={{ fill: COLOR.tick, fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                domain={[0, 1]}
              />
              <Tooltip cursor={false} contentStyle={TOOLTIP_STYLE} />
              <ReferenceLine
                segment={[
                  { x: 0, y: 0 },
                  { x: 1, y: 1 },
                ]}
                stroke={COLOR.brandDim}
                strokeDasharray="3 3"
                ifOverflow="extendDomain"
              />
              <Line
                type="monotone"
                dataKey="observed"
                stroke={COLOR.brand}
                strokeWidth={2.5}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Card>
    </div>
  );
}
