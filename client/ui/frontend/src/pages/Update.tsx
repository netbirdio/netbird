import { useEffect, useRef, useState } from "react";
import { Update as UpdateSvc } from "../../bindings/github.com/netbirdio/netbird/client/ui/services";

const TIMEOUT_MS = 15 * 60 * 1000;
const POLL_INTERVAL_MS = 2000;
// How long the daemon is allowed to be unreachable before we treat it as
// "daemon went down for the upgrade, treat as success and quit". Mirrors
// the legacy Fyne UI's branch in client/ui/update.go where a connection
// failure during polling is taken as the success signal.
const DAEMON_DOWN_GRACE_MS = 5000;

type Phase =
  | { kind: "running"; dots: number }
  | { kind: "timeout" }
  | { kind: "canceled" }
  | { kind: "failed"; message: string };

export default function Update() {
  const [phase, setPhase] = useState<Phase>({ kind: "running", dots: 1 });
  const phaseRef = useRef(phase);
  phaseRef.current = phase;

  const version = new URLSearchParams(
    window.location.hash.split("?")[1] ?? "",
  ).get("version");

  useEffect(() => {
    let cancelled = false;
    const start = Date.now();
    let firstUnreachableAt: number | null = null;

    UpdateSvc.Trigger().catch(() => {
      // The daemon may already be down (installer launched, daemon shutting
      // down). Don't treat as failure here; the poll loop's daemon-down
      // detection handles it.
    });

    const dotTimer = setInterval(() => {
      if (cancelled) return;
      setPhase((p) =>
        p.kind === "running" ? { kind: "running", dots: (p.dots % 3) + 1 } : p,
      );
    }, 1000);

    const pollTimer = setInterval(async () => {
      if (cancelled) return;
      if (phaseRef.current.kind !== "running") return;

      if (Date.now() - start > TIMEOUT_MS) {
        clearInterval(pollTimer);
        clearInterval(dotTimer);
        setPhase({ kind: "timeout" });
        return;
      }

      try {
        const r = await UpdateSvc.GetInstallerResult();
        firstUnreachableAt = null;
        if (r.success) {
          clearInterval(pollTimer);
          clearInterval(dotTimer);
          UpdateSvc.Quit();
          return;
        }
        if (r.errorMsg) {
          clearInterval(pollTimer);
          clearInterval(dotTimer);
          setPhase(mapInstallError(r.errorMsg));
        }
      } catch {
        // RPC failed. The daemon often goes away mid-upgrade — treat a
        // sustained outage as success and quit, matching the legacy UI.
        const now = Date.now();
        if (firstUnreachableAt === null) {
          firstUnreachableAt = now;
        } else if (now - firstUnreachableAt >= DAEMON_DOWN_GRACE_MS) {
          clearInterval(pollTimer);
          clearInterval(dotTimer);
          UpdateSvc.Quit();
        }
      }
    }, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(dotTimer);
      clearInterval(pollTimer);
    };
  }, []);

  const versionLine = version
    ? `Updating client to: ${version}.`
    : "Updating client.";

  return (
    <div className="flex h-full items-center justify-center p-6">
      <div className="space-y-3 text-center">
        <p className="whitespace-pre-line text-sm text-nb-gray-700 dark:text-nb-gray-200">
          {`Your client version is older than the auto-update version set in Management.\n${versionLine}`}
        </p>
        <p className="text-base font-medium">{statusText(phase)}</p>
      </div>
    </div>
  );
}

function statusText(p: Phase): string {
  switch (p.kind) {
    case "running":
      return "Updating" + ".".repeat(p.dots);
    case "timeout":
      return "Update timed out. Please try again.";
    case "canceled":
      return "Update canceled.";
    case "failed":
      return "Update failed: " + p.message;
  }
}

// Mirrors mapInstallError in client/ui/update.go. The daemon's installer
// surfaces error strings rather than typed errors, so the UI sniffs the
// message to decide whether to show the timeout/canceled wording.
function mapInstallError(msg: string): Phase {
  const m = msg.trim().toLowerCase();
  if (m === "") {
    return { kind: "failed", message: "unknown update error" };
  }
  if (m.includes("deadline exceeded") || m.includes("timeout")) {
    return { kind: "timeout" };
  }
  if (m.includes("canceled") || m.includes("cancelled")) {
    return { kind: "canceled" };
  }
  return { kind: "failed", message: msg };
}
