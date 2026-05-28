import { useEffect, useState } from "react";
import { Loader2, Play } from "lucide-react";
import { Card, CardTitle } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { api, type Scenario } from "@/lib/api";

export function AttackPanel() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<string | null>(null);

  useEffect(() => {
    api.scenarios().then(setScenarios).catch(() => {});
  }, []);

  const fire = async (key: string) => {
    setRunning(key);
    setLastResult(null);
    try {
      const r = await api.runScenario(key);
      setLastResult(`${key} — ${JSON.stringify(r.result).slice(0, 140)}`);
    } catch (e) {
      setLastResult(
        `error — ${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      setRunning(null);
    }
  };

  return (
    <Card>
      <div className="mb-4">
        <CardTitle>Attack Lab</CardTitle>
      </div>

      <div className="grid gap-2">
        {scenarios.map((s) => (
          <div
            key={s.key}
            className="flex items-center gap-3 rounded-input bg-canvas-dark p-3.5 hover:bg-surface-deep transition-colors"
          >
            <div className="min-w-0 flex-1 text-body-strong text-ink-onDark">
              {s.label}
            </div>
            <Button
              size="sm"
              variant="secondary"
              disabled={running !== null}
              onClick={() => fire(s.key)}
            >
              {running === s.key ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Play className="h-3.5 w-3.5" />
              )}
              Run
            </Button>
          </div>
        ))}
      </div>

      {lastResult && (
        <div className="mt-3 rounded-input bg-canvas-dark p-2.5 text-mono-md text-[11px] text-ink-onDarkMute max-h-20 overflow-y-auto">
          {lastResult}
        </div>
      )}
    </Card>
  );
}
