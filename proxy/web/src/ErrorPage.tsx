import { useEffect, useState } from "react";
import {BookText, RotateCw, Globe, UserIcon, WaypointsIcon} from "lucide-react";
import { Title } from "@/components/Title";
import { Description } from "@/components/Description";
import Button from "@/components/Button";
import { PoweredByNetBird } from "@/components/PoweredByNetBird";
import { StatusCard } from "@/components/StatusCard";
import type { ErrorData } from "@/data";

export function ErrorPage({ code, title, message, proxy = true, destination = true, requestId, simple = false, retryUrl }: Readonly<ErrorData>) {
  useEffect(() => {
    document.title = `${title} - NetBird Service`;
  }, [title]);

  const [timestamp] = useState(() => new Date().toISOString());

  return (
    <main className="flex flex-col items-center mt-24 px-4 max-w-3xl mx-auto">
      {/* Error Code */}
      <div className="text-sm text-netbird font-normal font-mono mb-3 z-10 relative">
        Error {code}
      </div>

      {/* Title */}
      <Title className="text-3xl!">{title}</Title>

      {/* Description */}
      <Description className="mt-2 mb-8 max-w-md">{message}</Description>

      {/* Status Cards - hidden in simple mode */}
      {!simple && (
        <div className="hidden sm:flex items-start justify-center w-full mt-6 mb-16 z-10 relative">
          <StatusCard icon={UserIcon} label="You" line={false} />
          <StatusCard icon={WaypointsIcon} label="Proxy" success={proxy} />
          <StatusCard icon={Globe} label="Destination" success={destination} />
        </div>
      )}

      {/* Buttons */}
      <div className="flex gap-3 justify-center items-center mb-6 z-10 relative">
        <Button variant="primary" onClick={() => {
          if (retryUrl) {
            globalThis.location.href = retryUrl;
          } else {
            globalThis.location.reload();
          }
        }}>
          <RotateCw size={16} />
          Refresh Page
        </Button>
        <Button
          variant="secondary"
          onClick={() => globalThis.open("https://docs.netbird.io", "_blank", "noopener,noreferrer")}
        >
          <BookText size={16} />
          Documentation
        </Button>
      </div>

      {/* Request Info */}
      <div className="text-center text-xs text-nb-gray-300 uppercase z-10 relative font-mono flex flex-col sm:flex-row gap-2 sm:gap-10 mt-4 mb-3">
        <div>
          <span className="text-nb-gray-400">REQUEST-ID:</span> {requestId}
        </div>
        <div>
          <span className="text-nb-gray-400">TIMESTAMP:</span> {timestamp}
        </div>
      </div>

      <PoweredByNetBird />
    </main>
  );
}
