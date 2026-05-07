import { useEffect, useState } from "react";
import { Events } from "@wailsio/runtime";
import { Peers } from "@bindings/services";
import type { Status } from "@bindings/services/models.js";

const EVENT_STATUS = "netbird:status";

// useStatus loads the current daemon status once and re-renders whenever the
// peers service emits a fresh snapshot over the Wails event bus.
export function useStatus(): { status: Status | null; error: string | null } {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Peers.Get()
      .then((s) => {
        if (!cancelled) setStatus(s);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(String(e));
      });

    const off = Events.On(EVENT_STATUS, (ev: { data: Status }) => {
      setStatus(ev.data);
      setError(null);
    });

    return () => {
      cancelled = true;
      off();
    };
  }, []);

  return { status, error };
}
