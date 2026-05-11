import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Network, ShieldCheck, Zap } from "lucide-react";
import { useStatus } from "../hooks/useStatus";
import type { PeerStatus } from "@bindings/services/models.js";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { cn } from "../lib/cn";

export default function Peers() {
  const { status } = useStatus();
  const [filter, setFilter] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const peers = useMemo(() => {
    const all = status?.peers ?? [];
    if (!filter.trim()) return all;
    const q = filter.trim().toLowerCase();
    return all.filter(
      (p) =>
        p.fqdn.toLowerCase().includes(q) ||
        p.ip.toLowerCase().includes(q) ||
        p.networks.some((n) => n.toLowerCase().includes(q)),
    );
  }, [status?.peers, filter]);

  return (
    <div className="flex h-full flex-col p-6">
      <div className="mb-3 flex items-center justify-between">
        <h1 className="text-xl font-semibold">
          Peers
          <span className="ml-2 text-sm font-normal text-nb-gray-500">
            {status?.peers?.length ?? 0}
          </span>
        </h1>
        <div className="w-64">
          <Input
            placeholder="Filter by FQDN / IP / network"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
      </div>

      {peers.length === 0 ? (
        <Card className="text-sm text-nb-gray-500">
          {status?.peers?.length === 0
            ? "No peers visible from this client."
            : "No peers match the filter."}
        </Card>
      ) : (
        <ul className="flex-1 divide-y divide-nb-gray-200 overflow-auto rounded-lg border border-nb-gray-200 dark:divide-nb-gray-800 dark:border-nb-gray-800">
          {peers.map((p) => (
            <PeerRow
              key={p.pubKey}
              peer={p}
              expanded={expanded === p.pubKey}
              onToggle={() => setExpanded(expanded === p.pubKey ? null : p.pubKey)}
            />
          ))}
        </ul>
      )}
    </div>
  );
}

function PeerRow({
  peer,
  expanded,
  onToggle,
}: {
  peer: PeerStatus;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <li>
      <button
        onClick={onToggle}
        className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-nb-gray-50 dark:hover:bg-nb-gray-940"
      >
        <ChevronIcon expanded={expanded} />
        <StateBadge state={peer.connStatus} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{peer.fqdn || "—"}</p>
          <p className="truncate font-mono text-xs text-nb-gray-500">{peer.ip}</p>
        </div>
        <RouteIcon relayed={peer.relayed} connected={peer.connStatus === "Connected"} />
        {peer.rosenpassEnabled && (
          <ShieldCheck className="h-4 w-4 text-green-500" strokeWidth={1.5} />
        )}
        <span className="w-16 text-right text-xs text-nb-gray-500">
          {peer.connStatus === "Connected" && peer.latencyMs > 0
            ? `${peer.latencyMs} ms`
            : ""}
        </span>
      </button>

      {expanded && <PeerDetails peer={peer} />}
    </li>
  );
}

function PeerDetails({ peer }: { peer: PeerStatus }) {
  return (
    <div className="grid grid-cols-2 gap-x-6 gap-y-2 bg-nb-gray-50 px-12 py-3 text-xs dark:bg-nb-gray-940">
      <Detail label="Public key" value={peer.pubKey} mono />
      <Detail label="Last handshake" value={fmtRelative(peer.lastHandshakeUnix)} />
      <Detail label="Status since" value={fmtRelative(peer.connStatusUpdateUnix)} />
      <Detail
        label="Bytes rx / tx"
        value={`${fmtBytes(peer.bytesRx)} / ${fmtBytes(peer.bytesTx)}`}
      />
      <Detail
        label="Local candidate"
        value={
          peer.localIceCandidateType
            ? `${peer.localIceCandidateType} (${peer.localIceCandidateEndpoint || "—"})`
            : "—"
        }
        mono
      />
      <Detail
        label="Remote candidate"
        value={
          peer.remoteIceCandidateType
            ? `${peer.remoteIceCandidateType} (${peer.remoteIceCandidateEndpoint || "—"})`
            : "—"
        }
        mono
      />
      {peer.relayed && (
        <Detail label="Relay" value={peer.relayAddress || "—"} mono />
      )}
      {peer.networks.length > 0 && (
        <Detail label="Networks" value={peer.networks.join(", ")} />
      )}
    </div>
  );
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex min-w-0 gap-2">
      <span className="shrink-0 text-nb-gray-500">{label}</span>
      <span
        className={cn(
          "min-w-0 truncate text-nb-gray-700 dark:text-nb-gray-200",
          mono && "font-mono",
        )}
      >
        {value}
      </span>
    </div>
  );
}

function ChevronIcon({ expanded }: { expanded: boolean }) {
  const Icon = expanded ? ChevronDown : ChevronRight;
  return <Icon className="h-4 w-4 shrink-0 text-nb-gray-400" strokeWidth={1.5} />;
}

function StateBadge({ state }: { state: string }) {
  const cls = "h-2 w-2 rounded-full shrink-0";
  switch (state) {
    case "Connected":
      return <span className={cn(cls, "bg-green-500")} title="Connected" />;
    case "Connecting":
      return <span className={cn(cls, "bg-netbird animate-pulse")} title="Connecting" />;
    case "Idle":
      return <span className={cn(cls, "bg-yellow-500")} title="Idle" />;
    default:
      return <span className={cn(cls, "bg-nb-gray-400")} title={state || "Disconnected"} />;
  }
}

function RouteIcon({ relayed, connected }: { relayed: boolean; connected: boolean }) {
  if (!connected) {
    return <span className="w-4 shrink-0" />;
  }
  if (relayed) {
    return (
      <Network
        className="h-4 w-4 text-yellow-600"
        strokeWidth={1.5}
      >
        <title>Relayed</title>
      </Network>
    );
  }
  return (
    <Zap className="h-4 w-4 text-green-600" strokeWidth={1.5}>
      <title>P2P</title>
    </Zap>
  );
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function fmtRelative(unixSec: number): string {
  if (!unixSec) return "—";
  const ageSec = Math.max(0, Math.floor(Date.now() / 1000) - unixSec);
  if (ageSec < 60) return `${ageSec}s ago`;
  if (ageSec < 3600) return `${Math.floor(ageSec / 60)}m ago`;
  if (ageSec < 86400) return `${Math.floor(ageSec / 3600)}h ago`;
  return `${Math.floor(ageSec / 86400)}d ago`;
}
