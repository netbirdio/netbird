import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ExternalLink, Loader2, AlertTriangle, X, RotateCcw } from "lucide-react";
import { Connection } from "../../bindings/github.com/netbirdio/netbird/client/ui/services";
import { Button } from "../components/Button";

type Phase = "starting" | "browser" | "connecting" | "error";

export default function Login() {
  const navigate = useNavigate();
  const [phase, setPhase] = useState<Phase>("starting");
  const [verificationUri, setVerificationUri] = useState<string>("");
  const [errorMsg, setErrorMsg] = useState<string>("");
  // attempt is bumped every time the user asks for a fresh start, which
  // re-arms the useEffect below so the daemon's Login RPC is dialed again.
  const [attempt, setAttempt] = useState(0);
  const cancelledRef = useRef(false);

  useEffect(() => {
    cancelledRef.current = false;
    setPhase("starting");
    setVerificationUri("");
    setErrorMsg("");

    (async () => {
      try {
        const result = await Connection.Login({
          profileName: "",
          username: "",
          managementUrl: "",
          setupKey: "",
          preSharedKey: "",
          hostname: "",
          hint: "",
        });
        if (cancelledRef.current) return;

        if (result.needsSsoLogin) {
          const uri = result.verificationUriComplete || result.verificationUri;
          setVerificationUri(uri);
          setPhase("browser");
          if (uri) Connection.OpenURL(uri).catch(console.error);

          await Connection.WaitSSOLogin({
            userCode: result.userCode,
            hostname: "",
          });
          if (cancelledRef.current) return;
        }

        setPhase("connecting");
        await Connection.Up({ profileName: "", username: "" });
        if (cancelledRef.current) return;

        navigate("/", { replace: true });
      } catch (e) {
        if (cancelledRef.current) return;
        setErrorMsg(String(e));
        setPhase("error");
      }
    })();

    return () => {
      cancelledRef.current = true;
    };
  }, [navigate, attempt]);

  // restart aborts any in-flight wait by toggling the cancellation flag,
  // tells the daemon to drop whatever it's holding (a stale WaitSSOLogin
  // can wedge the daemon for a previous UserCode), and then bumps attempt
  // so the effect re-runs with a clean slate.
  const restart = useCallback(async () => {
    cancelledRef.current = true;
    try {
      await Connection.Down();
    } catch (e) {
      console.error(e);
    }
    setAttempt((n) => n + 1);
  }, []);

  // Cancel must also tell the daemon to abandon the in-flight WaitSSOLogin.
  // Without Down(), the daemon stays parked on the OAuth flow's UserCode
  // forever; subsequent Login calls re-use the cached flow but the user has
  // no way out. Down() triggers the daemon's actCancel(), which unblocks
  // WaitSSOLogin with a context-canceled error so our promise settles.
  const cancel = useCallback(async () => {
    cancelledRef.current = true;
    try {
      await Connection.Down();
    } catch (e) {
      console.error(e);
    }
    navigate("/", { replace: true });
  }, [navigate]);

  if (phase === "error") {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 p-6 text-center">
        <AlertTriangle className="h-8 w-8 text-red-500" strokeWidth={1.5} />
        <h1 className="text-xl font-semibold">Login failed</h1>
        <p className="max-w-sm break-words text-sm text-nb-gray-500">{errorMsg}</p>
        <div className="flex gap-2">
          <Button onClick={restart}>
            <RotateCcw className="h-4 w-4" strokeWidth={1.5} /> Try again
          </Button>
          <Button variant="secondary" onClick={cancel}>
            Back
          </Button>
        </div>
      </div>
    );
  }

  if (phase === "browser") {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 p-6 text-center">
        <h1 className="text-xl font-semibold">Continue in your browser</h1>
        <p className="max-w-sm text-sm text-nb-gray-500">
          A browser tab should have opened. Sign in there — this window will
          continue automatically once you're done.
        </p>
        {verificationUri && (
          <Button onClick={() => Connection.OpenURL(verificationUri).catch(console.error)}>
            <ExternalLink className="h-4 w-4" strokeWidth={1.5} />
            Reopen URL
          </Button>
        )}
        <p className="max-w-sm break-all font-mono text-xs text-nb-gray-500">
          {verificationUri}
        </p>
        <div className="flex items-center gap-2 text-sm text-nb-gray-500">
          <Loader2 className="h-4 w-4 animate-spin" strokeWidth={1.5} />
          Waiting for sign-in…
        </div>
        <div className="flex gap-2 pt-2">
          <Button variant="secondary" onClick={restart}>
            <RotateCcw className="h-4 w-4" strokeWidth={1.5} /> Restart
          </Button>
          <Button variant="ghost" onClick={cancel}>
            <X className="h-4 w-4" strokeWidth={1.5} /> Cancel
          </Button>
        </div>
      </div>
    );
  }

  const message =
    phase === "connecting" ? "Bringing the connection up…" : "Starting login…";
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center">
      <Loader2 className="h-8 w-8 animate-spin text-netbird" strokeWidth={1.5} />
      <p className="text-sm text-nb-gray-500">{message}</p>
      <Button variant="ghost" onClick={cancel}>
        <X className="h-4 w-4" strokeWidth={1.5} /> Cancel
      </Button>
    </div>
  );
}
