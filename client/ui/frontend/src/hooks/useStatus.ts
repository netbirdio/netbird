import { useCallback, useEffect, useState } from "react";
import { Events } from "@wailsio/runtime";
import { Peers } from "@bindings/services";
import type { Status } from "@bindings/services/models.js";

const EVENT_STATUS = "netbird:status";

// useStatus loads the current daemon status once and re-renders whenever the
// peers service emits a fresh snapshot over the Wails event bus. Callers can
// also force a manual refresh (e.g. right after Connection.Up/Down) so the
// view never lags behind a user action even if the daemon event stream is
// briefly silent.
export function useStatus(): {
  status: Status | null;
  error: string | null;
  refresh: () => Promise<void>;
} {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const s = await Peers.Get();
      setStatus(s);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();

    const off = Events.On(EVENT_STATUS, (ev: { data: Status }) => {
      setStatus(ev.data);
      setError(null);
    });

    return () => {
      off();
    };
  }, [refresh]);

  return { status, error, refresh };
}
