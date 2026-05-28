import { type ButtonHTMLAttributes, forwardRef } from "react";
import { cn } from "@/lib/utils";

type Variant = "primary" | "secondary" | "ghost" | "brand" | "danger";
type Size = "sm" | "md";

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

const VARIANT_CLS: Record<Variant, string> = {
  // Hero CTA — at most one per viewport. White pill on dark.
  primary:
    "bg-canvas-light text-canvas-dark hover:bg-ink-onDarkMute disabled:bg-ink-onDarkFaint disabled:text-canvas-dark/60",
  // Default action. Surface-elevated on canvas.
  secondary:
    "bg-surface-elevated text-ink-onDark hover:bg-white/10 disabled:opacity-50",
  // Tertiary action. Outline only.
  ghost:
    "bg-transparent text-ink-onDark border border-hairline-dark hover:bg-white/5 disabled:opacity-50",
  // Reserved highlight CTA — cobalt-violet stamp.
  brand:
    "bg-brand text-white hover:bg-brand-bright disabled:bg-brand-deep disabled:opacity-60",
  // Destructive.
  danger:
    "bg-transparent text-verdict-block border border-verdict-block/30 hover:bg-verdict-block/10 disabled:opacity-50",
};

const SIZE_CLS: Record<Size, string> = {
  sm: "h-8 px-4 text-button gap-1.5",
  md: "h-10 px-5 text-button gap-2",
};

export const Button = forwardRef<HTMLButtonElement, Props>(
  ({ className, variant = "secondary", size = "md", ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center rounded-pill",
          "transition-colors duration-150 disabled:cursor-not-allowed",
          SIZE_CLS[size],
          VARIANT_CLS[variant],
          className,
        )}
        {...props}
      />
    );
  },
);
Button.displayName = "Button";
