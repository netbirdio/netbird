import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ExternalLink, Loader2, AlertTriangle } from "lucide-react";
import { Connection } from "../../bindings/github.com/netbirdio/netbird/client/ui-wails/services";
import { Button } from "../components/Button";

type Phase = "starting" | "browser" | "connecting" | "error";

export default function Login() {
  const navigate = useNavigate();
  const [phase, setPhase] = useState<Phase>("starting");
  const [verificationUri, setVerificationUri] = useState<string>("");
  const [errorMsg, setErrorMsg] = useState<string>("");
  const startedRef = useRef(false);

  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;

    let cancelled = false;
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
        if (cancelled) return;

        if (result.needsSsoLogin) {
          const uri = result.verificationUriComplete || result.verificationUri;
          setVerificationUri(uri);
          setPhase("browser");
          if (uri) Connection.OpenURL(uri).catch(console.error);

          await Connection.WaitSSOLogin({
            userCode: result.userCode,
            hostname: "",
          });
          if (cancelled) return;
        }

        setPhase("connecting");
        await Connection.Up({ profileName: "", username: "" });
        if (cancelled) return;

        navigate("/", { replace: true });
      } catch (e) {
        if (cancelled) return;
        setErrorMsg(String(e));
        setPhase("error");
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [navigate]);

  if (phase === "error") {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 p-6 text-center">
        <AlertTriangle className="h-8 w-8 text-red-500" strokeWidth={1.5} />
        <h1 className="text-xl font-semibold">Login failed</h1>
        <p className="max-w-sm break-words text-sm text-nb-gray-500">{errorMsg}</p>
        <Button onClick={() => navigate("/", { replace: true })}>Back</Button>
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
      </div>
    );
  }

  const message =
    phase === "connecting" ? "Bringing the connection up…" : "Starting login…";
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center">
      <Loader2 className="h-8 w-8 animate-spin text-netbird" strokeWidth={1.5} />
      <p className="text-sm text-nb-gray-500">{message}</p>
    </div>
  );
}
