import { useLocation } from "react-router-dom";
import { Badge } from "@/components/ui/Badge";

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

  return (
    <header className="sticky top-0 z-20 flex items-center justify-between gap-4 bg-canvas-dark border-b border-hairline-dark px-6 py-3">
      <div className="text-heading-sm text-ink-onDark">{title}</div>
      <Badge tone={connected ? "allow" : "block"} dot pulse={connected}>
        {connected ? "stream live" : "reconnecting"}
      </Badge>
    </header>
  );
}
