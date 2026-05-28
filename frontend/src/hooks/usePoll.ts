import { useEffect, useState } from "react";

export function usePoll<T>(fn: () => Promise<T>, intervalMs = 3000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let stopped = false;
    const tick = async () => {
      try {
        const v = await fn();
        if (!stopped) setData(v);
      } catch (e) {
        if (!stopped) setError(e);
      }
    };
    tick();
    const id = window.setInterval(tick, intervalMs);
    return () => {
      stopped = true;
      window.clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs]);

  return { data, error };
}
