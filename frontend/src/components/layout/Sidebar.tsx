import { NavLink } from "react-router-dom";
import { Activity, Brain, Radar, Users } from "lucide-react";
import { cn } from "@/lib/utils";

const items = [
  { to: "/", label: "Overview", icon: Activity },
  { to: "/sessions", label: "Sessions", icon: Users },
  { to: "/lab", label: "Attack Lab", icon: Radar },
  { to: "/ml", label: "ML Insights", icon: Brain },
];

export function Sidebar() {
  return (
    <aside className="hidden md:flex md:w-60 flex-col bg-canvas-dark border-r border-hairline-dark">
      <div className="px-6 py-6">
        <div className="text-heading-lg text-ink-onDark tracking-tight">
          Sentinel
        </div>
      </div>

      <nav className="flex-1 px-3 py-2 space-y-1">
        {items.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-input px-3 py-2 text-body",
                "text-ink-onDarkMute transition-colors duration-150",
                "hover:bg-white/5 hover:text-ink-onDark",
                isActive && "bg-surface-elevated text-ink-onDark",
              )
            }
          >
            <Icon className="h-4 w-4" />
            <span className="text-body-strong">{label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
