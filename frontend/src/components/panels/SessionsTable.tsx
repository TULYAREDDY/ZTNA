import { useEffect, useState } from "react";
import { Trash2 } from "lucide-react";
import { Card, CardTitle } from "@/components/ui/Card";
import { Badge, type BadgeTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { api, type SessionView } from "@/lib/api";
import { cn, formatRelative, riskTextClass, shortId } from "@/lib/utils";

const STATUS_TONE: Record<SessionView["status"], BadgeTone> = {
  ACTIVE: "allow",
  REVOKED: "block",
  EXPIRED: "muted",
};

const COLUMN_HEADERS = [
  "Status",
  "User",
  "Device",
  "IP",
  "Risk",
  "Posture",
  "Reqs",
  "Last seen",
  "",
];

const POLL_INTERVAL_MS = 2500;
const MAX_BACKOFF_MULTIPLIER = 8;

export function SessionsTable() {
  const [rows, setRows] = useState<SessionView[]>([]);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timeoutId: number;
    let backoff = 1;
    const load = async () => {
      try {
        const data = await api.sessions(false);
        if (cancelled) return;
        setRows(data);
        backoff = 1;
      } catch {
        /* ignore — next poll will retry, with backoff */
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MULTIPLIER);
      } finally {
        if (!cancelled) {
          timeoutId = window.setTimeout(load, POLL_INTERVAL_MS * backoff);
        }
      }
    };
    load();
    return () => {
      cancelled = true;
      window.clearTimeout(timeoutId);
    };
  }, []);

  const revoke = async (sid: string) => {
    setBusy(sid);
    try {
      await api.revoke(sid, "revoked from console");
      setRows((rs) =>
        rs.map((r) =>
          r.session_id === sid ? { ...r, status: "REVOKED" } : r,
        ),
      );
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card>
      <div className="flex items-center justify-between mb-4">
        <CardTitle>Sessions</CardTitle>
        <span className="text-caption text-ink-onDarkDim">
          {rows.length} total
        </span>
      </div>

      <div className="overflow-x-auto -mx-2">
        <table className="w-full">
          <thead>
            <tr className="text-left">
              {COLUMN_HEADERS.map((h, i) => (
                <th
                  key={i}
                  className="px-2 py-2 text-eyebrow text-ink-onDarkDim font-normal"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td
                  colSpan={COLUMN_HEADERS.length}
                  className="px-2 py-10 text-center text-body text-ink-onDarkDim"
                >
                  No sessions yet.
                </td>
              </tr>
            )}
            {rows.map((r) => {
              const tone = STATUS_TONE[r.status] ?? "muted";
              return (
                <tr
                  key={r.session_id}
                  className="border-t border-hairline-soft hover:bg-white/3 transition-colors"
                >
                  <td className="px-2 py-3">
                    <Badge tone={tone} dot pulse={r.status === "ACTIVE"}>
                      {r.status.toLowerCase()}
                    </Badge>
                  </td>
                  <td className="px-2 py-3">
                    <div className="text-body-strong text-ink-onDark">
                      {r.user_id}
                    </div>
                    <div className="text-mono-md text-ink-onDarkFaint">
                      sid {shortId(r.session_id, 8)}
                    </div>
                  </td>
                  <td className="px-2 py-3">
                    <div className="text-body text-ink-onDarkMute">{r.os}</div>
                    <div className="text-mono-md text-ink-onDarkFaint">
                      {shortId(r.device_id, 8)}
                    </div>
                  </td>
                  <td className="px-2 py-3">
                    <div className="text-mono-md text-ink-onDarkMute">
                      {r.ip_address}
                    </div>
                    <div className="text-caption text-ink-onDarkFaint">
                      {r.geo_country}
                    </div>
                  </td>
                  <td
                    className={cn(
                      "px-2 py-3 text-mono-md",
                      riskTextClass(r.risk_score),
                    )}
                  >
                    {r.risk_score}
                  </td>
                  <td className="px-2 py-3 text-mono-md text-ink-onDarkMute">
                    {r.posture_score}
                  </td>
                  <td className="px-2 py-3 text-mono-md text-ink-onDarkMute">
                    <span>{r.request_count}</span>
                    {r.block_count > 0 && (
                      <span className="ml-1 text-verdict-block">
                        ({r.block_count} blk)
                      </span>
                    )}
                  </td>
                  <td className="px-2 py-3 text-caption text-ink-onDarkDim">
                    {formatRelative(r.last_seen_at)}
                  </td>
                  <td className="px-2 py-3 text-right">
                    {r.status === "ACTIVE" && (
                      <Button
                        size="sm"
                        variant="danger"
                        disabled={busy === r.session_id}
                        onClick={() => revoke(r.session_id)}
                      >
                        <Trash2 className="h-3 w-3" />
                        Revoke
                      </Button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
