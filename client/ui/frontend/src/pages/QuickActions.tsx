import { CheckCircle2, Circle, Loader2, Power } from "lucide-react";
import { useStatus } from "../hooks/useStatus";
import { Connection } from "../../bindings/github.com/netbirdio/netbird/client/ui/services";
import { Button } from "../components/Button";
import { cn } from "../lib/cn";

export default function QuickActions() {
  const { status } = useStatus();
  const state = status?.status ?? "Disconnected";
  const connected = state === "Connected";
  const connecting = state === "Connecting";

  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 p-6">
      <Icon state={state} />
      <p className="text-lg font-medium">{state}</p>
      {connected ? (
        <Button variant="secondary" onClick={() => Connection.Down()}>
          Disconnect
        </Button>
      ) : (
        <Button onClick={() => Connection.Up({ profileName: "", username: "" })} disabled={connecting}>
          <Power className="h-4 w-4" strokeWidth={1.5} /> Connect
        </Button>
      )}
    </div>
  );
}

function Icon({ state }: { state: string }) {
  const cls = "h-12 w-12";
  switch (state) {
    case "Connected":
      return <CheckCircle2 className={cn(cls, "text-green-500")} strokeWidth={1.5} />;
    case "Connecting":
      return <Loader2 className={cn(cls, "animate-spin text-netbird")} strokeWidth={1.5} />;
    default:
      return <Circle className={cn(cls, "text-nb-gray-400")} strokeWidth={1.5} />;
  }
}
