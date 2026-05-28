import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { BadgeTone } from "@/components/ui/Badge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatRelative(iso: string): string {
  const ts = new Date(iso).getTime();
  if (Number.isNaN(ts)) return "—";
  const diff = (Date.now() - ts) / 1000;
  if (diff < 1) return "just now";
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return new Date(iso).toLocaleString();
}

export function shortId(id: string | null | undefined, n = 8): string {
  if (!id) return "—";
  return id.length <= n ? id : `${id.slice(0, n)}…`;
}

/**
 * Map a decision string ("ALLOW" | "MONITOR" | "BLOCK") to a Badge tone.
 * Unknown decisions fall back to neutral.
 */
export function decisionTone(d?: string | null): BadgeTone {
  switch (d) {
    case "ALLOW":
      return "allow";
    case "MONITOR":
      return "monitor";
    case "BLOCK":
      return "block";
    default:
      return "neutral";
  }
}

/**
 * Map a numeric risk score to a verdict tone using the same thresholds
 * as the backend (block ≥ 70, monitor ≥ 45, allow otherwise).
 */
export function verdictTone(
  score: number | null | undefined,
): "allow" | "monitor" | "block" {
  const s = score ?? 0;
  if (s >= 70) return "block";
  if (s >= 45) return "monitor";
  return "allow";
}

/** Tailwind text-color class for a numeric risk score. */
export function riskTextClass(score: number | null | undefined): string {
  const tone = verdictTone(score);
  if (tone === "block") return "text-verdict-block";
  if (tone === "monitor") return "text-verdict-monitor";
  return "text-verdict-allow";
}
