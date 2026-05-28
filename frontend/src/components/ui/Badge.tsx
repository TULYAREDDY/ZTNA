import { type HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export type BadgeTone = "allow" | "monitor" | "block" | "neutral" | "muted";

interface Props extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
  /** Render a leading status dot in the matching tone. */
  dot?: boolean;
  /** Make the dot blink (for live / active states). */
  pulse?: boolean;
}

const TONE_CLS: Record<BadgeTone, string> = {
  allow: "bg-verdict-allow/12 text-verdict-allow ring-verdict-allow/30",
  monitor: "bg-verdict-monitor/12 text-verdict-monitor ring-verdict-monitor/30",
  block: "bg-verdict-block/12 text-verdict-block ring-verdict-block/30",
  neutral: "bg-surface-elevated text-ink-onDark ring-hairline-dark",
  muted: "bg-white/8 text-ink-onDarkMute ring-hairline-dark",
};

const DOT_CLS: Record<BadgeTone, string> = {
  allow: "bg-verdict-allow",
  monitor: "bg-verdict-monitor",
  block: "bg-verdict-block",
  neutral: "bg-ink-onDarkDim",
  muted: "bg-ink-onDarkDim",
};

export function Badge({
  className,
  tone = "neutral",
  dot = false,
  pulse = false,
  children,
  ...props
}: Props) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-pill px-2.5 py-0.5",
        "text-[11px] font-semibold uppercase tracking-[0.12em]",
        "ring-1 ring-inset",
        TONE_CLS[tone],
        className,
      )}
      {...props}
    >
      {dot && (
        <span
          className={cn(
            "h-1.5 w-1.5 rounded-full",
            DOT_CLS[tone],
            pulse && "animate-blink",
          )}
        />
      )}
      {children}
    </span>
  );
}
