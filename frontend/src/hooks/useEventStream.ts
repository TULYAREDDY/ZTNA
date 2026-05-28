import {
  createContext,
  createElement,
  type ReactNode,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import { eventsWebSocketUrl, type EventView } from "@/lib/api";

interface Ctx {
  events: EventView[];
  connected: boolean;
}

const EventCtx = createContext<Ctx>({ events: [], connected: false });

export function EventStreamProvider({
  children,
  maxBuffer = 300,
}: {
  children: ReactNode;
  maxBuffer?: number;
}) {
  const [events, setEvents] = useState<EventView[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let stopped = false;
    let retry = 0;

    const connect = () => {
      const ws = new WebSocket(eventsWebSocketUrl());
      wsRef.current = ws;
      ws.onopen = () => {
        retry = 0;
        setConnected(true);
      };
      ws.onclose = () => {
        setConnected(false);
        if (stopped) return;
        retry = Math.min(retry + 1, 6);
        setTimeout(connect, 500 * 2 ** retry);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        try {
          const ev: EventView = JSON.parse(e.data);
          if (ev.kind === "PING") return;
          setEvents((prev) => {
            const next = [ev, ...prev];
            return next.length > maxBuffer ? next.slice(0, maxBuffer) : next;
          });
        } catch {
          /* ignore */
        }
      };
    };

    connect();
    return () => {
      stopped = true;
      wsRef.current?.close();
    };
  }, [maxBuffer]);

  return createElement(EventCtx.Provider, { value: { events, connected } }, children);
}

export function useEventStream() {
  return useContext(EventCtx);
}
