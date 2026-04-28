import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";
import { Update as UpdateSvc } from "../../bindings/github.com/netbirdio/netbird/client/ui-wails/services";

const TIMEOUT_MS = 15 * 60 * 1000;

export default function Update() {
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    UpdateSvc.Trigger().catch((e) => !cancelled && setError(String(e)));

    const start = Date.now();
    const timer = setInterval(async () => {
      if (Date.now() - start > TIMEOUT_MS) {
        setError("Update timed out.");
        clearInterval(timer);
        return;
      }
      try {
        const r = await UpdateSvc.GetInstallerResult();
        if (r.success) {
          setDone(true);
          clearInterval(timer);
        } else if (r.errorMsg) {
          setError(r.errorMsg);
          clearInterval(timer);
        }
      } catch {
        // installer not finished yet
      }
    }, 2000);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <div className="flex h-full items-center justify-center p-6">
      <div className="text-center">
        {done ? (
          <h1 className="text-xl font-semibold text-green-500">Update complete</h1>
        ) : error ? (
          <h1 className="text-xl font-semibold text-red-500">{error}</h1>
        ) : (
          <>
            <Loader2 className="mx-auto mb-3 h-8 w-8 animate-spin text-netbird" strokeWidth={1.5} />
            <h1 className="text-xl font-semibold">Updating…</h1>
            <p className="mt-1 text-sm text-nb-gray-500">
              Please don't close this window.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
