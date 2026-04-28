import { CheckCircle2, Circle, Loader2, AlertTriangle, Power } from "lucide-react";
import { useStatus } from "../hooks/useStatus";
import { Connection } from "../../bindings/github.com/netbirdio/netbird/client/ui-wails/services";
import type { SystemEvent } from "../../bindings/github.com/netbirdio/netbird/client/ui-wails/services/models.js";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { cn } from "../lib/cn";

export default function Status() {
  const { status, error } = useStatus();

  const connState = status?.status ?? "Disconnected";
  const connected = connState === "Connected";
  const connecting = connState === "Connecting";

  const connect = () => Connection.Up({ profileName: "", username: "" }).catch(console.error);
  const disconnect = () => Connection.Down().catch(console.error);

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <StateIcon state={connState} />
          <div>
            <h1 className="text-xl font-semibold leading-none">{connState}</h1>
            <p className="mt-1 text-sm text-nb-gray-500">
              {status?.local.fqdn || "—"}
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button onClick={connect} disabled={connected || connecting}>
            <Power className="h-4 w-4" strokeWidth={1.5} /> Connect
          </Button>
          <Button onClick={disconnect} variant="secondary" disabled={!connected}>
            Disconnect
          </Button>
        </div>
      </div>

      {error && (
        <div className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200">
          <AlertTriangle className="mt-0.5 h-4 w-4" strokeWidth={1.5} />
          <span>{error}</span>
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        <InfoCard label="Local IP" value={status?.local.ip || "—"} />
        <InfoCard label="Peers" value={String(status?.peers?.length ?? 0)} />
        <LinkCard label="Management" link={status?.management} />
        <LinkCard label="Signal" link={status?.signal} />
      </div>

      <Card>
        <h2 className="mb-3 text-sm font-semibold text-nb-gray-700 dark:text-nb-gray-200">
          Recent events
        </h2>
        {(() => {
          const events = dedupEvents(status?.events ?? []).slice(0, 8);
          if (events.length === 0) {
            return <p className="text-sm text-nb-gray-500">No recent events.</p>;
          }
          return (
            <ul className="space-y-2 text-sm">
              {events.map((e, i) => (
                <li key={`${e.id}-${i}`} className="flex gap-2">
                  <span className="shrink-0 font-mono text-xs text-nb-gray-500">
                    {e.severity}
                  </span>
                  <span className="text-nb-gray-700 dark:text-nb-gray-200">
                    {e.userMessage || e.message}
                  </span>
                </li>
              ))}
            </ul>
          );
        })()}
      </Card>
    </div>
  );
}

function StateIcon({ state }: { state: string }) {
  const cls = "h-7 w-7";
  switch (state) {
    case "Connected":
      return <CheckCircle2 className={cn(cls, "text-green-500")} strokeWidth={1.5} />;
    case "Connecting":
      return <Loader2 className={cn(cls, "animate-spin text-netbird")} strokeWidth={1.5} />;
    case "Error":
      return <AlertTriangle className={cn(cls, "text-red-500")} strokeWidth={1.5} />;
    default:
      return <Circle className={cn(cls, "text-nb-gray-400")} strokeWidth={1.5} />;
  }
}

function InfoCard({ label, value }: { label: string; value: string }) {
  return (
    <Card>
      <p className="text-xs uppercase tracking-wide text-nb-gray-500">{label}</p>
      <p className="mt-1 truncate font-mono text-sm">{value}</p>
    </Card>
  );
}

// dedupEvents collapses repeated daemon events that carry the same logical
// content. The daemon emits one "new_version_available" event per check tick,
// so its 10-event ring buffer fills with duplicates after a quiet hour. Same
// goes for periodic "DNS unreachable" or "auth retry" events. We key by
// message + a small set of identity-bearing metadata fields and keep the
// newest occurrence (the events array is already in publish order).
function dedupEvents(events: SystemEvent[]): SystemEvent[] {
  const seen = new Set<string>();
  const out: SystemEvent[] = [];
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i];
    const md = e.metadata ?? {};
    const key = [
      e.severity,
      e.category,
      e.userMessage || e.message,
      md["new_version_available"] ?? "",
      md["enforced"] ?? "",
    ].join("|");
    // eslint-disable-next-line no-console
    console.log("[dedup]", { key, event: e });
    if (seen.has(key)) continue;
    seen.add(key);
    out.unshift(e);
  }
  return out;
}

function LinkCard({
  label,
  link,
}: {
  label: string;
  link?: { url: string; connected: boolean; error?: string };
}) {
  return (
    <Card>
      <div className="flex items-center justify-between">
        <p className="text-xs uppercase tracking-wide text-nb-gray-500">{label}</p>
        <span
          className={cn(
            "h-2 w-2 rounded-full",
            link?.connected ? "bg-green-500" : "bg-nb-gray-400",
          )}
        />
      </div>
      <p className="mt-1 truncate text-xs text-nb-gray-600 dark:text-nb-gray-300">
        {link?.url || "—"}
      </p>
      {link?.error && (
        <p className="mt-1 truncate text-xs text-red-500">{link.error}</p>
      )}
    </Card>
  );
}
