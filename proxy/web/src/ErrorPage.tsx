import { useEffect, useState } from "react";
import { BookText, RotateCw, Globe, UserIcon, WaypointsIcon, ShieldAlert, LockKeyhole, BadgeX } from "lucide-react";
import { Title } from "@/components/Title";
import { Description } from "@/components/Description";
import Button from "@/components/Button";
import { PoweredByNetBird } from "@/components/PoweredByNetBird";
import { StatusCard } from "@/components/StatusCard";
import { Card } from "@/components/Card";
import { cn } from "@/utils/helpers";
import type { ErrorData } from "@/data";

function ForbiddenPage({ code, title, message, requestId, retryUrl }: Readonly<ErrorData>) {
  const [timestamp] = useState(() => new Date().toISOString());

  return (
    <main className="min-h-screen px-4 py-10 flex items-center justify-center">
      <div className="w-full max-w-4xl">
        <Card className="overflow-hidden px-0 py-0">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(246,131,48,0.16),transparent_35%),radial-gradient(circle_at_bottom_right,rgba(240,82,82,0.12),transparent_30%)] pointer-events-none" />
          <div className="relative grid lg:grid-cols-[1.1fr_0.9fr]">
            <div className="px-6 sm:px-10 py-8 sm:py-10 border-b border-nb-gray-910 lg:border-b-0 lg:border-r lg:border-r-nb-gray-910">
              <div className="inline-flex items-center gap-2 rounded-full border border-netbird/25 bg-netbird/10 px-3 py-1 text-xs font-mono uppercase tracking-[0.22em] text-netbird">
                <ShieldAlert size={14} />
                Error {code}
              </div>

              <Title className="mt-6 text-3xl! sm:text-4xl!">Forbidden</Title>
              <Description className="mt-3 max-w-lg text-base text-nb-gray-250">
                {message || "This service is protected by access rules. Your current connection is reaching the proxy, but it is not allowed to open this destination."}
              </Description>

              <div className="mt-8 grid gap-3 sm:grid-cols-3">
                <ForbiddenSignal
                  icon={UserIcon}
                  title="Identity Check"
                  text="Your request reached the protected entry point."
                />
                <ForbiddenSignal
                  icon={LockKeyhole}
                  title="Policy Gate"
                  text="An access rule or private-network check blocked this request."
                  accent="warn"
                />
                <ForbiddenSignal
                  icon={BadgeX}
                  title="Service Access"
                  text="The destination stays closed until permission requirements are met."
                />
              </div>
            </div>

            <div className="px-6 sm:px-10 py-8 sm:py-10">
              <div className="rounded-2xl border border-nb-gray-910 bg-nb-gray-950/40 p-5">
                <div className="flex items-center gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-red-800/40 bg-red-900/20 text-red-400">
                    <ShieldAlert size={20} />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-nb-gray-100">Access blocked by policy</p>
                    <p className="mt-1 text-sm text-nb-gray-350">
                      Confirm that this peer is connected through NetBird and allowed by the reverse proxy policy.
                    </p>
                  </div>
                </div>

                <div className="mt-5 space-y-3">
                  <div className="rounded-xl border border-nb-gray-910 bg-nb-gray-930/50 px-4 py-3">
                    <p className="text-[11px] font-mono uppercase tracking-[0.22em] text-nb-gray-400">Request ID</p>
                    <p className="mt-2 break-all font-mono text-xs text-nb-gray-200">{requestId || "Unavailable"}</p>
                  </div>
                  <div className="rounded-xl border border-nb-gray-910 bg-nb-gray-930/50 px-4 py-3">
                    <p className="text-[11px] font-mono uppercase tracking-[0.22em] text-nb-gray-400">Timestamp</p>
                    <p className="mt-2 font-mono text-xs text-nb-gray-200">{timestamp}</p>
                  </div>
                </div>

                <div className="mt-6 flex flex-col gap-3 sm:flex-row">
                  <Button
                    variant="primary"
                    className="w-full sm:flex-1"
                    onClick={() => {
                      if (retryUrl) {
                        globalThis.location.href = retryUrl;
                      } else {
                        globalThis.location.reload();
                      }
                    }}
                  >
                    <RotateCw size={16} />
                    Try Again
                  </Button>
                  <Button
                    variant="secondary"
                    className="w-full sm:flex-1"
                    onClick={() => globalThis.open("https://docs.netbird.io", "_blank", "noopener,noreferrer")}
                  >
                    <BookText size={16} />
                    View Docs
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </Card>
        <PoweredByNetBird />
      </div>
    </main>
  );
}

function ForbiddenSignal({
  icon: Icon,
  title,
  text,
  accent = "default",
}: Readonly<{
  icon: typeof UserIcon;
  title: string;
  text: string;
  accent?: "default" | "warn";
}>) {
  return (
    <div className="rounded-2xl border border-nb-gray-910 bg-nb-gray-950/30 p-4">
      <div
        className={cn(
          "flex h-10 w-10 items-center justify-center rounded-xl border mb-4",
          accent === "warn"
            ? "border-netbird/30 bg-netbird/10 text-netbird"
            : "border-nb-gray-900 bg-nb-gray-930/80 text-nb-gray-150"
        )}
      >
        <Icon size={18} />
      </div>
      <p className="text-sm font-medium text-nb-gray-100">{title}</p>
      <p className="mt-2 text-sm text-nb-gray-350">{text}</p>
    </div>
  );
}

export function ErrorPage({ code, title, message, proxy = true, destination = true, requestId, simple = false, variant = "connection", retryUrl }: Readonly<ErrorData>) {
  useEffect(() => {
    document.title = `${title} - NetBird Service`;
  }, [title]);

  if (variant === "forbidden") {
    return <ForbiddenPage code={code} title={title} message={message} requestId={requestId} retryUrl={retryUrl} />;
  }

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
