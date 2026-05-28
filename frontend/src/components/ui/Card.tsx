import { type HTMLAttributes, forwardRef } from "react";
import { cn } from "@/lib/utils";

export const Card = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn("bg-surface-elevated rounded-card p-5", className)}
      {...props}
    />
  ),
);
Card.displayName = "Card";

/** Uppercase kicker that sits at the top-left of every card. */
export function CardTitle({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("text-eyebrow text-ink-onDarkMute", className)}
      {...props}
    />
  );
}

/** Small caption below a CardTitle. Use sparingly; only when the title alone leaves a real ambiguity. */
export function CardSubtitle({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("text-caption text-ink-onDarkDim mt-1", className)}
      {...props}
    />
  );
}
