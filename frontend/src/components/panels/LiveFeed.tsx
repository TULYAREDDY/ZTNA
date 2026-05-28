import { AnimatePresence, motion } from "framer-motion";
import {
  AlertTriangle,
  Ban,
  Check,
  Eye,
  ShieldOff,
  Timer,
} from "lucide-react";
import { Card, CardTitle } from "@/components/ui/Card";
import { Badge, type BadgeTone } from "@/components/ui/Badge";
import type { EventView } from "@/lib/api";
import { cn, decisionTone, formatRelative, shortId } from "@/lib/utils";

interface Props {
  events: EventView[];
  connected: boolean;
}

const KIND_ICON = {
  POSTURE: ShieldOff,
  ACCESS: Check,
  REVOKE: Ban,
  EXPIRE: Timer,
} as const;

const DECISION_ICON = {
  ALLOW: Check,
  MONITOR: Eye,
  BLOCK: AlertTriangle,
} as const;

const ICON_BG: Record<BadgeTone, string> = {
  allow: "bg-verdict-allow/12 text-verdict-allow",
  monitor: "bg-verdict-monitor/12 text-verdict-monitor",
  block: "bg-verdict-block/12 text-verdict-block",
  neutral: "bg-white/5 text-ink-onDarkMute",
  muted: "bg-white/5 text-ink-onDarkMute",
};

const TEXT_TONE: Record<BadgeTone, string> = {
  allow: "text-verdict-allow",
  monitor: "text-verdict-monitor",
  block: "text-verdict-block",
  neutral: "text-ink-onDarkMute",
  muted: "text-ink-onDarkMute",
};

const MAX_VISIBLE_EVENTS = 80;
const MAX_REASON_CHIPS = 4;

function decisionIcon(d?: string | null) {
  return DECISION_ICON[d as keyof typeof DECISION_ICON] ?? Check;
}

export function LiveFeed({ events, connected }: Props) {
  return (
    <Card className="flex flex-col h-[560px]">
      <div className="flex items-start justify-between mb-4">
        <CardTitle>Live Feed</CardTitle>
        <Badge tone={connected ? "allow" : "block"} dot pulse={connected}>
          {connected ? "live" : "offline"}
        </Badge>
      </div>

      <div className="flex-1 overflow-y-auto pr-1 -mr-1">
        {events.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center text-ink-onDarkDim">
            <div className="text-body">Waiting for traffic.</div>
            <div className="mt-1 text-caption text-ink-onDarkFaint">
              Trigger a scenario in Attack Lab.
            </div>
          </div>
        ) : (
          <ul className="space-y-2">
            <AnimatePresence initial={false}>
              {events.slice(0, MAX_VISIBLE_EVENTS).map((e) => {
                const tone = decisionTone(e.decision);
                const Icon = decisionIcon(e.decision);
                const KindIcon =
                  KIND_ICON[e.kind as keyof typeof KIND_ICON] ?? Check;
                return (
                  <motion.li
                    key={e.id}
                    layout
                    initial={{ opacity: 0, x: -6 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.18 }}
                    className="rounded-input bg-canvas-dark p-3 hover:bg-surface-deep transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={cn(
                          "flex h-8 w-8 items-center justify-center rounded-tile shrink-0",
                          ICON_BG[tone],
                        )}
                      >
                        <Icon className="h-4 w-4" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className={cn("text-eyebrow", TEXT_TONE[tone])}>
                            {e.decision ?? e.kind}
                          </span>
                          <span className="flex items-center gap-1 text-eyebrow text-ink-onDarkFaint">
                            <KindIcon className="h-3 w-3" />
                            {e.kind}
                          </span>
                          {e.risk_score != null && (
                            <span className="ml-auto text-mono-md text-ink-onDarkDim">
                              risk{" "}
                              <span className="text-ink-onDark">
                                {e.risk_score}
                              </span>
                            </span>
                          )}
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-caption text-ink-onDarkDim">
                          {e.user_id && (
                            <span>
                              user{" "}
                              <span className="text-ink-onDarkMute">
                                {e.user_id}
                              </span>
                            </span>
                          )}
                          {e.ip_address && (
                            <span className="text-mono-md text-ink-onDarkMute">
                              {e.ip_address}
                            </span>
                          )}
                          {e.target_service && (
                            <span>
                              →{" "}
                              <span className="text-ink-onDarkMute">
                                {e.target_service}
                              </span>
                            </span>
                          )}
                          {e.session_id && (
                            <span className="text-mono-md text-ink-onDarkFaint">
                              sid {shortId(e.session_id, 6)}
                            </span>
                          )}
                          <span className="ml-auto text-ink-onDarkFaint">
                            {formatRelative(e.ts)}
                          </span>
                        </div>
                        {e.reasons && e.reasons.length > 0 && (
                          <div className="mt-1.5 flex flex-wrap gap-1">
                            {e.reasons.slice(0, MAX_REASON_CHIPS).map((r) => (
                              <span
                                key={r}
                                className="rounded-input bg-white/5 px-1.5 py-0.5 text-mono-md text-[10px] text-ink-onDarkMute"
                              >
                                {r}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </motion.li>
                );
              })}
            </AnimatePresence>
          </ul>
        )}
      </div>
    </Card>
  );
}
