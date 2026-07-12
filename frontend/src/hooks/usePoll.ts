import { useEffect, useState } from "react";

const MAX_BACKOFF_MULTIPLIER = 8;

export function usePoll<T>(fn: () => Promise<T>, intervalMs = 3000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let stopped = false;
    let timeoutId: number;
    let backoff = 1;

    const tick = async () => {
      try {
        const v = await fn();
        if (stopped) return;
        setData(v);
        setError(null);
        backoff = 1;
      } catch (e) {
        if (stopped) return;
        setError(e);
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MULTIPLIER);
      } finally {
        if (!stopped) timeoutId = window.setTimeout(tick, intervalMs * backoff);
      }
    };

    tick();
    return () => {
      stopped = true;
      window.clearTimeout(timeoutId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs]);

  return { data, error };
}
