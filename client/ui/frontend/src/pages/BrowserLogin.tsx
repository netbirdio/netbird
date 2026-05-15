import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import { Loader2 } from "lucide-react";
import { Connection } from "@bindings/services";
import { Button } from "../components/Button";
import netbirdFull from "@/assets/logos/netbird-full.svg";

const EVENT_CANCEL = "browser-login:cancel";

export default function BrowserLogin() {
  const [params] = useSearchParams();
  const uri = params.get("uri") ?? "";

  const tryAgain = useCallback(() => {
    if (!uri) return;
    Connection.OpenURL(uri).catch(console.error);
  }, [uri]);

  const cancel = useCallback(() => {
    void Events.Emit(EVENT_CANCEL);
  }, []);

  return (
    <div className="flex h-screen flex-col items-center justify-center gap-3 p-8 text-center">
      <img src={netbirdFull} alt="NetBird" className="mb-2 h-9" />
      <h1 className="text-lg font-semibold text-white">
        Continue in your browser to complete the login
      </h1>
      <p className="max-w-sm text-sm text-nb-gray-400">
        Please complete the account authentication process in the browser tab
        and continue from there.
      </p>
      <div className="flex items-center gap-2 text-sm text-nb-gray-400">
        <Loader2 className="h-4 w-4 animate-spin" strokeWidth={1.5} />
        Waiting for sign-in…
      </div>
      <p className="text-sm text-nb-gray-400">
        Not seeing the browser tab?{" "}
        <button
          type="button"
          onClick={tryAgain}
          disabled={!uri}
          className="text-netbird hover:underline disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Try again
        </button>
      </p>
      <Button variant="secondary" onClick={cancel} className="mt-2">
        Cancel
      </Button>
    </div>
  );
}
