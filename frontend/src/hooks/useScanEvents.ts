import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type { ScanEvent } from "../types";

export interface LiveScanState {
  events: ScanEvent[];
  logs: ScanEvent[];
  agents: Record<string, string>;
  tools: Record<string, string>;
  state: string | null;
  progress: number;
  findingsCount: number;
}

const INITIAL: LiveScanState = {
  events: [],
  logs: [],
  agents: {},
  tools: {},
  state: null,
  progress: 0,
  findingsCount: 0,
};

export function useScanEvents(scanId: number, enabled: boolean) {
  const [state, setState] = useState<LiveScanState>(INITIAL);
  const [connected, setConnected] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  const applyEvent = useCallback((event: ScanEvent) => {
    setState((prev) => {
      const next: LiveScanState = {
        ...prev,
        events: [...prev.events.slice(-600), event],
      };
      if (event.type === "log") {
        next.logs = [...prev.logs.slice(-400), event];
      }
      if (event.type === "progress") {
        next.progress = event.progress ?? prev.progress;
        next.state = event.state ?? prev.state;
      }
      if (event.type === "state") {
        next.state = event.state ?? prev.state;
      }
      if (event.type === "agent" && event.agent) {
        next.agents = { ...prev.agents, [event.agent]: event.status || "RUNNING" };
      }
      if (event.type === "tool" && event.tool) {
        next.tools = { ...prev.tools, [event.tool]: event.status || "RUNNING" };
      }
      if (event.type === "finding") {
        next.findingsCount = prev.findingsCount + 1;
      }
      return next;
    });
  }, []);

  useEffect(() => {
    if (!enabled) return;
    const es = new EventSource(`${api.base}/api/scans/${scanId}/events`);
    esRef.current = es;
    es.onopen = () => setConnected(true);
    es.onmessage = (msg) => {
      if (msg.data && !msg.data.startsWith(":") && msg.data.trim()) {
        try {
          applyEvent(JSON.parse(msg.data));
        } catch {
          /* ignore malformed */
        }
      }
    };
    es.onerror = () => {
      setConnected(false);
    };
    return () => {
      es.close();
      esRef.current = null;
    };
  }, [scanId, enabled, applyEvent]);

  return { ...state, connected };
}
