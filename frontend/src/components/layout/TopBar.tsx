import { useLocation } from "react-router-dom";
import { Badge } from "@/components/ui/Badge";
import { usePoll } from "@/hooks/usePoll";
import { api } from "@/lib/api";

interface Props {
  connected: boolean;
}

const TITLES: Record<string, string> = {
  "/": "Overview",
  "/sessions": "Sessions",
  "/lab": "Attack Lab",
  "/ml": "ML Insights",
};

export function TopBar({ connected }: Props) {
  const { pathname } = useLocation();
  const title = TITLES[pathname] ?? "Console";
  const { data: health } = usePoll(api.health, 10000);
  const mlActive = health?.ml?.trained ?? false;

  return (
    <header className="sticky top-0 z-20 flex items-center justify-between gap-4 bg-canvas-dark border-b border-hairline-dark px-6 py-3">
      <div className="text-heading-sm text-ink-onDark">{title}</div>
      <div className="flex items-center gap-2">
        <Badge tone={mlActive ? "allow" : "monitor"} dot={mlActive}>
          {mlActive ? "ml active" : "ml inactive — rules only"}
        </Badge>
        <Badge tone={connected ? "allow" : "block"} dot pulse={connected}>
          {connected ? "stream live" : "reconnecting"}
        </Badge>
      </div>
    </header>
  );
}
