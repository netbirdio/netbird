import { useEffect, useState } from "react";
import { ExternalLink } from "lucide-react";
import { Connection } from "../../bindings/github.com/netbirdio/netbird/client/ui/services";
import { Button } from "../components/Button";

export default function LoginUrl() {
  const [url, setUrl] = useState<string>("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.split("?")[1] ?? "");
    setUrl(params.get("url") ?? "");
  }, []);

  if (!url) {
    return (
      <div className="flex h-full items-center justify-center p-6 text-sm text-nb-gray-500">
        No login URL provided.
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 p-6 text-center">
      <h1 className="text-xl font-semibold">Continue in your browser</h1>
      <p className="max-w-sm text-sm text-nb-gray-500">
        Open the following URL to finish signing in.
      </p>
      <Button onClick={() => Connection.OpenURL(url).catch(console.error)}>
        <ExternalLink className="h-4 w-4" strokeWidth={1.5} />
        Open URL
      </Button>
      <p className="max-w-sm break-all font-mono text-xs text-nb-gray-500">{url}</p>
    </div>
  );
}
