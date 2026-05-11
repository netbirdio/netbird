import { useState } from "react";
<<<<<<<< HEAD:client/ui/frontend/src/screens/Debug.tsx
import { Debug as DebugSvc } from "@bindings/services";
import type { DebugBundleResult } from "@bindings/services/models.js";
========
import { Debug as DebugSvc } from "../../bindings/github.com/netbirdio/netbird/client/ui/services";
import type { DebugBundleResult } from "../../bindings/github.com/netbirdio/netbird/client/ui/services/models.js";
>>>>>>>> ui-refactor:client/ui/frontend/src/pages/Debug.tsx
import { Button } from "../components/Button";
import { Input } from "../components/Input";
import { Switch } from "../components/Switch";
import { Card } from "../components/Card";

export default function Debug() {
  const [anonymize, setAnonymize] = useState(true);
  const [systemInfo, setSystemInfo] = useState(true);
  const [upload, setUpload] = useState(false);
  const [uploadUrl, setUploadUrl] = useState("");
  const [logFiles, setLogFiles] = useState(0);

  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<DebugBundleResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setRunning(true);
    setResult(null);
    setError(null);
    try {
      const r = await DebugSvc.Bundle({
        anonymize,
        systemInfo,
        uploadUrl: upload ? uploadUrl : "",
        logFileCount: logFiles,
      });
      setResult(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-4 p-6">
      <h1 className="text-xl font-semibold">Debug bundle</h1>

      <Card className="space-y-4">
        <Switch
          checked={anonymize}
          onChange={setAnonymize}
          label="Anonymize"
          description="Replace IPs and identifiers in the bundle."
        />
        <Switch
          checked={systemInfo}
          onChange={setSystemInfo}
          label="Include system information"
        />
        <Switch
          checked={upload}
          onChange={setUpload}
          label="Upload on create"
        />
        {upload && (
          <Input
            label="Upload URL"
            value={uploadUrl}
            onChange={(e) => setUploadUrl(e.target.value)}
          />
        )}
        <Input
          label="Log file count"
          type="number"
          value={logFiles}
          onChange={(e) => setLogFiles(Number(e.target.value))}
        />
        <div className="pt-2">
          <Button onClick={run} disabled={running}>
            {running ? "Generating…" : "Create bundle"}
          </Button>
        </div>
      </Card>

      {error && <p className="text-sm text-red-500">{error}</p>}

      {result && (
        <Card>
          {result.path && (
            <p className="text-sm">
              <span className="text-nb-gray-500">Path:</span>{" "}
              <span className="font-mono">{result.path}</span>
            </p>
          )}
          {result.uploadedKey && (
            <p className="text-sm">
              <span className="text-nb-gray-500">Uploaded key:</span>{" "}
              <span className="font-mono">{result.uploadedKey}</span>
            </p>
          )}
          {result.uploadFailureReason && (
            <p className="text-sm text-red-500">
              Upload failed: {result.uploadFailureReason}
            </p>
          )}
        </Card>
      )}
    </div>
  );
}
