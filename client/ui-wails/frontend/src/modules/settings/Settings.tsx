import { useCallback, useEffect, useRef, useState } from "react";
import { Browser } from "@wailsio/runtime";
import {
    Settings as SettingsSvc,
    Profiles as ProfilesSvc,
    Update as UpdateSvc,
    Debug as DebugSvc,
    Connection as ConnectionSvc,
} from "../../../bindings/github.com/netbirdio/netbird/client/ui-wails/services";
import type {
    Config,
    DebugBundleResult,
} from "../../../bindings/github.com/netbirdio/netbird/client/ui-wails/services/models.js";
import { Check, Copy, FolderOpen, Loader2 } from "lucide-react";
import netbirdAppIcon from "@/assets/logos/netbird-app-icon.svg";
import pkg from "../../../package.json";
import { useStatus } from "@/hooks/useStatus";
import { Button } from "@/components/Button";
import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { HelpText } from "@/components/HelpText";
import { Input } from "@/components/Input";
import { Label } from "@/components/Label";
import { cn } from "@/lib/cn";
import { MainRightSide } from "@/layouts/MainRightSide.tsx";
import { VerticalTabs } from "@/components/VerticalTabs.tsx";
import { SettingsNavigationTriggers } from "@/modules/settings/SettingsNavigationTriggers.tsx";

type Ctx = {
    cfg: Config;
    setField: <K extends keyof Config>(k: K, v: Config[K]) => void;
};

const SAVE_DEBOUNCE_MS = 400;

const buildPayload = (
    cfg: Config,
    profileName: string,
    username: string,
) => ({
    profileName,
    username,
    managementUrl: cfg.managementUrl,
    adminUrl: cfg.adminUrl,
    interfaceName: cfg.interfaceName,
    wireguardPort: cfg.wireguardPort,
    mtu: cfg.mtu,
    preSharedKey: cfg.preSharedKey,
    disableAutoConnect: cfg.disableAutoConnect,
    serverSshAllowed: cfg.serverSshAllowed,
    rosenpassEnabled: cfg.rosenpassEnabled,
    rosenpassPermissive: cfg.rosenpassPermissive,
    disableNotifications: cfg.disableNotifications,
    lazyConnectionEnabled: cfg.lazyConnectionEnabled,
    blockInbound: cfg.blockInbound,
    networkMonitor: cfg.networkMonitor,
    disableClientRoutes: cfg.disableClientRoutes,
    disableServerRoutes: cfg.disableServerRoutes,
    disableDns: cfg.disableDns,
    blockLanAccess: cfg.blockLanAccess,
    enableSshRoot: cfg.enableSshRoot,
    enableSshSftp: cfg.enableSshSftp,
    enableSshLocalPortForwarding: cfg.enableSshLocalPortForwarding,
    enableSshRemotePortForwarding: cfg.enableSshRemotePortForwarding,
    disableSshAuth: cfg.disableSshAuth,
    sshJwtCacheTtl: cfg.sshJwtCacheTtl,
});

export const Settings = () => {
    const [active, setActive] = useState("general");
    const [username, setUsername] = useState("");
    const [profile, setProfile] = useState("");
    const [cfg, setCfg] = useState<Config | null>(null);
    const [error, setError] = useState<string | null>(null);
    const dirtyRef = useRef(false);

    const load = useCallback(async () => {
        try {
            const u = await ProfilesSvc.Username();
            const activeProfile = await ProfilesSvc.GetActive();
            const profileName = activeProfile.profileName || "default";
            setUsername(u);
            setProfile(profileName);
            const c = await SettingsSvc.GetConfig({
                profileName,
                username: u,
            });
            setCfg(c);
            setError(null);
        } catch (e) {
            setError(String(e));
        }
    }, []);

    useEffect(() => {
        load();
    }, [load]);

    const setField: Ctx["setField"] = (k, v) => {
        dirtyRef.current = true;
        setCfg((c) => (c ? { ...c, [k]: v } : c));
    };

    const saveNow = useCallback(async () => {
        if (!cfg) return;
        try {
            await SettingsSvc.SetConfig(buildPayload(cfg, profile, username));
            setError(null);
        } catch (e) {
            setError(String(e));
        }
    }, [cfg, profile, username]);

    useEffect(() => {
        if (!cfg || !dirtyRef.current) return;
        const t = setTimeout(saveNow, SAVE_DEBOUNCE_MS);
        return () => clearTimeout(t);
    }, [cfg, saveNow]);

    return (
        <VerticalTabs
            value={active}
            onValueChange={setActive}
            className={"wails-draggable p-4"}
        >
                <SettingsNavigationTriggers />
            <MainRightSide>
                {error && (
                    <p className={"px-6 py-2 text-sm text-red-500"}>{error}</p>
                )}
                <div className={"flex-1 min-h-0 overflow-y-auto"}>
                    {!cfg ? (
                        <div className={"p-6 text-sm text-nb-gray-500"}>
                            Loading…
                        </div>
                    ) : (
                        <div className={"px-6 py-5"}>
                            <VerticalTabs.Content value={"general"}>
                                <GeneralSection
                                    cfg={cfg}
                                    setField={setField}
                                    onSaveServer={saveNow}
                                />
                            </VerticalTabs.Content>
                            <VerticalTabs.Content value={"network"}>
                                <NetworkSection cfg={cfg} setField={setField} />
                            </VerticalTabs.Content>
                            <VerticalTabs.Content value={"security"}>
                                <SecuritySection
                                    cfg={cfg}
                                    setField={setField}
                                />
                            </VerticalTabs.Content>
                            <VerticalTabs.Content value={"ssh"}>
                                <SshSection cfg={cfg} setField={setField} />
                            </VerticalTabs.Content>
                            <VerticalTabs.Content value={"advanced"}>
                                <AdvancedSection
                                    cfg={cfg}
                                    setField={setField}
                                />
                            </VerticalTabs.Content>
                            <VerticalTabs.Content value={"troubleshooting"}>
                                <TroubleshootingSection
                                    profile={profile}
                                    username={username}
                                />
                            </VerticalTabs.Content>
                            <VerticalTabs.Content value={"about"}>
                                <AboutSection />
                            </VerticalTabs.Content>
                        </div>
                    )}
                </div>
            </MainRightSide>
        </VerticalTabs>
    );
};

const SectionGroup = ({
    title,
    children,
}: {
    title: string;
    children: React.ReactNode;
}) => (
    <section className={"mb-8"}>
        <h2
            className={
                "text-xs uppercase tracking-wider text-nb-gray-400 mb-3 font-semibold"
            }
        >
            {title}
        </h2>
        <div className={"flex flex-col gap-4"}>{children}</div>
    </section>
);

function GeneralSection({
    cfg,
    setField,
    onSaveServer,
}: Ctx & { onSaveServer: () => void | Promise<void> }) {
    return (
        <>
            <SectionGroup title={"General"}>
                <FancyToggleSwitch
                    value={!cfg.disableAutoConnect}
                    onChange={(v) => setField("disableAutoConnect", !v)}
                    label={"Connect on startup"}
                    helpText={
                        "Automatically connect to NetBird when the app launches."
                    }
                />
                <FancyToggleSwitch
                    value={!cfg.disableNotifications}
                    onChange={(v) => setField("disableNotifications", !v)}
                    label={"Show notifications"}
                    helpText={
                        "Show desktop notifications for connection events and updates."
                    }
                />
            </SectionGroup>

            <SectionGroup title={"Connection"}>
                <div>
                    <Label as={"div"}>Management Server</Label>
                    <HelpText>
                        The NetBird management server this client connects to.
                        Saving will reconnect to apply the new server.
                    </HelpText>
                    <div className={"flex items-center gap-2"}>
                        <div className={"flex-1"}>
                            <Input
                                value={cfg.managementUrl}
                                onChange={(e) =>
                                    setField("managementUrl", e.target.value)
                                }
                            />
                        </div>
                        <Button
                            variant={"primary"}
                            size={"md"}
                            onClick={() => onSaveServer()}
                        >
                            Save
                        </Button>
                    </div>
                </div>
            </SectionGroup>
        </>
    );
}

function NetworkSection({ cfg, setField }: Ctx) {
    return (
        <>
            <SectionGroup title={"Connectivity"}>
                <FancyToggleSwitch
                    value={cfg.lazyConnectionEnabled}
                    onChange={(v) => setField("lazyConnectionEnabled", v)}
                    label={"Lazy connections"}
                    helpText={
                        "Only establish peer tunnels on first traffic instead of eagerly at startup."
                    }
                />
                <FancyToggleSwitch
                    value={cfg.networkMonitor}
                    onChange={(v) => setField("networkMonitor", v)}
                    label={"Network monitor"}
                    helpText={
                        "Reconnect automatically when the host network changes (Wi-Fi switch, VPN, sleep/wake)."
                    }
                />
            </SectionGroup>

            <SectionGroup title={"Routing & DNS"}>
                <FancyToggleSwitch
                    value={!cfg.disableDns}
                    onChange={(v) => setField("disableDns", !v)}
                    label={"Enable DNS"}
                    helpText={
                        "Apply NetBird-managed DNS settings to the host resolver."
                    }
                />
                <FancyToggleSwitch
                    value={!cfg.disableClientRoutes}
                    onChange={(v) => setField("disableClientRoutes", !v)}
                    label={"Enable client routes"}
                    helpText={
                        "Accept routes advertised by other peers so this client can reach their networks."
                    }
                />
                <FancyToggleSwitch
                    value={!cfg.disableServerRoutes}
                    onChange={(v) => setField("disableServerRoutes", !v)}
                    label={"Enable server routes"}
                    helpText={
                        "Advertise this host's local routes to other peers."
                    }
                />
            </SectionGroup>
        </>
    );
}

function SecuritySection({ cfg, setField }: Ctx) {
    return (
        <>
            <SectionGroup title={"Firewall"}>
                <FancyToggleSwitch
                    value={cfg.blockInbound}
                    onChange={(v) => setField("blockInbound", v)}
                    label={"Block inbound traffic"}
                    helpText={
                        "Drop all unsolicited inbound traffic on the NetBird interface."
                    }
                />
                <FancyToggleSwitch
                    value={cfg.blockLanAccess}
                    onChange={(v) => setField("blockLanAccess", v)}
                    label={"Block LAN access"}
                    helpText={
                        "Prevent peers from reaching this host's local network."
                    }
                />
            </SectionGroup>

            <SectionGroup title={"Encryption"}>
                <FancyToggleSwitch
                    value={cfg.rosenpassEnabled}
                    onChange={(v) => setField("rosenpassEnabled", v)}
                    label={"Quantum-resistant encryption"}
                    helpText={
                        "Add a post-quantum key exchange (Rosenpass) on top of WireGuard."
                    }
                >
                    <FancyToggleSwitch
                        value={cfg.rosenpassPermissive}
                        onChange={(v) => setField("rosenpassPermissive", v)}
                        label={"Permissive mode"}
                        helpText={
                            "Allow connections to peers without quantum-resistance support."
                        }
                    />
                </FancyToggleSwitch>
            </SectionGroup>
        </>
    );
}

function SshSection({ cfg, setField }: Ctx) {
    const sshOff = !cfg.serverSshAllowed;
    return (
        <>
            <SectionGroup title={"Server"}>
                <FancyToggleSwitch
                    value={cfg.serverSshAllowed}
                    onChange={(v) => setField("serverSshAllowed", v)}
                    label={"Allow SSH"}
                    helpText={
                        "Run the NetBird SSH server on this host so other peers can connect to it."
                    }
                />
            </SectionGroup>

            <SectionGroup title={"Capabilities"}>
                <FancyToggleSwitch
                    value={cfg.enableSshRoot}
                    onChange={(v) => setField("enableSshRoot", v)}
                    label={"Allow root login"}
                    helpText={
                        "Permit incoming SSH sessions to authenticate as root."
                    }
                    disabled={sshOff}
                />
                <FancyToggleSwitch
                    value={cfg.enableSshSftp}
                    onChange={(v) => setField("enableSshSftp", v)}
                    label={"Enable SFTP"}
                    helpText={"Allow file transfers over the NetBird SSH server."}
                    disabled={sshOff}
                />
                <FancyToggleSwitch
                    value={cfg.enableSshLocalPortForwarding}
                    onChange={(v) => setField("enableSshLocalPortForwarding", v)}
                    label={"Local port forwarding"}
                    helpText={
                        "Allow clients to forward local ports through this host."
                    }
                    disabled={sshOff}
                />
                <FancyToggleSwitch
                    value={cfg.enableSshRemotePortForwarding}
                    onChange={(v) =>
                        setField("enableSshRemotePortForwarding", v)
                    }
                    label={"Remote port forwarding"}
                    helpText={
                        "Allow clients to expose remote ports back through this host."
                    }
                    disabled={sshOff}
                />
            </SectionGroup>

            <SectionGroup title={"Authentication"}>
                <FancyToggleSwitch
                    value={cfg.disableSshAuth}
                    onChange={(v) => setField("disableSshAuth", v)}
                    label={"Disable SSH auth"}
                    helpText={
                        "Skip JWT authentication for incoming SSH sessions. Insecure — diagnostics only."
                    }
                    disabled={sshOff}
                />
                <div
                    className={cn(
                        "flex items-center gap-6",
                        sshOff && "opacity-50 pointer-events-none",
                    )}
                >
                    <div className={"flex-1 max-w-md"}>
                        <Label as={"div"}>JWT cache TTL</Label>
                        <HelpText margin={false}>
                            How long verified JWTs are cached before
                            re-validation. Shorter values increase load on the
                            management server; longer values delay revocation.
                        </HelpText>
                    </div>
                    <div className={"w-32 shrink-0"}>
                        <Input
                            type={"number"}
                            value={cfg.sshJwtCacheTtl}
                            onChange={(e) =>
                                setField(
                                    "sshJwtCacheTtl",
                                    Number(e.target.value),
                                )
                            }
                            customSuffix={
                                <span className={"text-nb-gray-400"}>s</span>
                            }
                            disabled={sshOff}
                        />
                    </div>
                </div>
            </SectionGroup>
        </>
    );
}

function AdvancedSection({ cfg, setField }: Ctx) {
    return (
        <>
            <SectionGroup title={"Security"}>
                <div>
                    <Label as={"div"}>Pre-shared key</Label>
                    <HelpText>
                        Optional WireGuard pre-shared key for an extra layer of
                        symmetric encryption. Must match the value configured
                        on every peer in the network.
                    </HelpText>
                    <Input
                        type={"password"}
                        showPasswordToggle
                        value={cfg.preSharedKey}
                        onChange={(e) =>
                            setField("preSharedKey", e.target.value)
                        }
                    />
                </div>
            </SectionGroup>

            <SectionGroup title={"Interface"}>
                <Input
                    label={"Name"}
                    value={cfg.interfaceName}
                    onChange={(e) => setField("interfaceName", e.target.value)}
                />
                <div className={"grid grid-cols-2 gap-4"}>
                    <Input
                        label={"WireGuard Port"}
                        type={"number"}
                        value={cfg.wireguardPort}
                        onChange={(e) =>
                            setField("wireguardPort", Number(e.target.value))
                        }
                    />
                    <Input
                        label={"MTU"}
                        type={"number"}
                        value={cfg.mtu}
                        onChange={(e) =>
                            setField("mtu", Number(e.target.value))
                        }
                    />
                </div>
            </SectionGroup>
        </>
    );
}

const NETBIRD_UPLOAD_URL = "https://debug.netbird.io/upload";
const TRACE_LOG_FILE_COUNT = 5;
const PLAIN_LOG_FILE_COUNT = 1;

type Stage =
    | { kind: "idle" }
    | { kind: "preparing-trace" }
    | { kind: "reconnecting" }
    | { kind: "capturing"; remainingSec: number; totalSec: number }
    | { kind: "restoring-level" }
    | { kind: "bundling" }
    | { kind: "uploading" }
    | { kind: "done"; result: DebugBundleResult; uploadAttempted: boolean }
    | { kind: "error"; message: string };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function TroubleshootingSection({
    profile,
    username,
}: {
    profile: string;
    username: string;
}) {
    const [anonymize, setAnonymize] = useState(true);
    const [systemInfo, setSystemInfo] = useState(true);
    const [upload, setUpload] = useState(false);
    const [trace, setTrace] = useState(false);
    const [traceMinutes, setTraceMinutes] = useState(3);
    const [stage, setStage] = useState<Stage>({ kind: "idle" });

    const isRunning =
        stage.kind !== "idle" &&
        stage.kind !== "done" &&
        stage.kind !== "error";

    const reset = () => setStage({ kind: "idle" });

    const run = async () => {
        const uploadUrl = upload ? NETBIRD_UPLOAD_URL : "";
        try {
            let originalLevel = "info";
            if (trace) {
                setStage({ kind: "preparing-trace" });
                try {
                    const cur = await DebugSvc.GetLogLevel();
                    if (cur?.level) originalLevel = cur.level;
                } catch {
                    // best effort
                }
                await DebugSvc.SetLogLevel({ level: "trace" });

                setStage({ kind: "reconnecting" });
                try {
                    await ConnectionSvc.Down();
                } catch {
                    // already down
                }
                await ConnectionSvc.Up({ profileName: profile, username });

                const totalSec = Math.max(
                    1,
                    Math.min(30, traceMinutes),
                ) * 60;
                for (let remaining = totalSec; remaining > 0; remaining--) {
                    setStage({
                        kind: "capturing",
                        remainingSec: remaining,
                        totalSec,
                    });
                    await sleep(1000);
                }

                setStage({ kind: "restoring-level" });
                try {
                    await DebugSvc.SetLogLevel({ level: originalLevel });
                } catch {
                    // restore is best-effort
                }
            }

            setStage({ kind: "bundling" });
            const logFileCount = trace
                ? TRACE_LOG_FILE_COUNT
                : PLAIN_LOG_FILE_COUNT;

            if (uploadUrl) setStage({ kind: "uploading" });
            const result = await DebugSvc.Bundle({
                anonymize,
                systemInfo,
                uploadUrl,
                logFileCount,
            });
            setStage({
                kind: "done",
                result,
                uploadAttempted: Boolean(uploadUrl),
            });
        } catch (e) {
            setStage({ kind: "error", message: String(e) });
        }
    };

    return (
        <SectionGroup title={"Debug bundle"}>
            <p className={"text-sm text-nb-gray-300 mb-2"}>
                A debug bundle helps NetBird support investigate connection
                problems. It's a zip file with logs and system details from
                this device.
            </p>

            <FancyToggleSwitch
                value={anonymize}
                onChange={setAnonymize}
                label={"Anonymize personal data"}
                helpText={
                    "Replace IPs, hostnames, and peer names before saving."
                }
                disabled={isRunning}
            />
            <FancyToggleSwitch
                value={systemInfo}
                onChange={setSystemInfo}
                label={"Include system info"}
                helpText={
                    "Include OS, kernel, network interfaces, and routing tables."
                }
                disabled={isRunning}
            />
            <FancyToggleSwitch
                value={upload}
                onChange={setUpload}
                label={"Send to NetBird support"}
                helpText={
                    "Uploads the bundle directly. You'll get a key to share with us."
                }
                disabled={isRunning}
            />
            <FancyToggleSwitch
                value={trace}
                onChange={setTrace}
                label={"Capture detailed (trace) logs"}
                helpText={
                    "Restart NetBird with extra logging for a few minutes, then create the bundle. NetBird will briefly disconnect."
                }
                disabled={isRunning}
            >
                <div className={"flex items-center gap-3 max-w-sm"}>
                    <Label as={"div"} className={"!mb-0"}>
                        Capture for
                    </Label>
                    <div className={"w-24"}>
                        <Input
                            type={"number"}
                            min={1}
                            max={30}
                            value={traceMinutes}
                            onChange={(e) =>
                                setTraceMinutes(
                                    Math.max(
                                        1,
                                        Math.min(
                                            30,
                                            Number(e.target.value) || 1,
                                        ),
                                    ),
                                )
                            }
                            customSuffix={
                                <span className={"text-nb-gray-400"}>min</span>
                            }
                            disabled={isRunning}
                        />
                    </div>
                </div>
            </FancyToggleSwitch>

            <div className={"flex items-center gap-3 mt-2"}>
                <Button
                    variant={"primary"}
                    size={"md"}
                    onClick={run}
                    disabled={isRunning}
                >
                    {isRunning ? "Creating bundle…" : "Create bundle"}
                </Button>
                {stage.kind === "error" && (
                    <Button
                        variant={"secondary"}
                        size={"md"}
                        onClick={reset}
                    >
                        Try again
                    </Button>
                )}
            </div>

            <BundleStatus stage={stage} />
        </SectionGroup>
    );
}

function BundleStatus({ stage }: { stage: Stage }) {
    if (stage.kind === "idle") return null;

    if (
        stage.kind === "preparing-trace" ||
        stage.kind === "reconnecting" ||
        stage.kind === "capturing" ||
        stage.kind === "restoring-level" ||
        stage.kind === "bundling" ||
        stage.kind === "uploading"
    ) {
        return (
            <div
                className={
                    "mt-4 flex items-center gap-3 rounded-md border border-nb-gray-800 bg-nb-gray-920 px-4 py-3"
                }
            >
                <Loader2
                    className={"animate-spin text-netbird shrink-0"}
                    size={18}
                />
                <p className={"text-sm text-nb-gray-200"}>
                    {stageLabel(stage)}
                </p>
            </div>
        );
    }

    if (stage.kind === "error") {
        return (
            <div
                className={
                    "mt-4 rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300"
                }
            >
                {stage.message}
            </div>
        );
    }

    return <BundleResult result={stage.result} uploaded={stage.uploadAttempted} />;
}

function stageLabel(stage: Stage): string {
    switch (stage.kind) {
        case "preparing-trace":
            return "Switching to trace logging…";
        case "reconnecting":
            return "Reconnecting NetBird…";
        case "capturing": {
            const fmt = (s: number) =>
                `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
            return `Capturing logs — ${fmt(
                stage.totalSec - stage.remainingSec,
            )} / ${fmt(stage.totalSec)}`;
        }
        case "restoring-level":
            return "Restoring previous log level…";
        case "bundling":
            return "Building bundle…";
        case "uploading":
            return "Uploading to NetBird…";
        default:
            return "";
    }
}

function BundleResult({
    result,
    uploaded,
}: {
    result: DebugBundleResult;
    uploaded: boolean;
}) {
    const uploadFailed = uploaded && !result.uploadedKey;
    return (
        <div className={"mt-4 flex flex-col gap-3"}>
            {uploaded && result.uploadedKey && (
                <div
                    className={
                        "rounded-md border border-nb-gray-800 bg-nb-gray-920 px-4 py-4"
                    }
                >
                    <p className={"text-sm font-medium mb-1"}>
                        Bundle uploaded
                    </p>
                    <p className={"text-xs text-nb-gray-400 mb-3"}>
                        Share this key with NetBird support so they can find
                        your bundle.
                    </p>
                    <CopyableValue value={result.uploadedKey} mono large />
                </div>
            )}

            {uploadFailed && (
                <div
                    className={
                        "rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300"
                    }
                >
                    Upload failed
                    {result.uploadFailureReason
                        ? `: ${result.uploadFailureReason}`
                        : "."}{" "}
                    The bundle is still saved locally.
                </div>
            )}

            {result.path && (
                <div
                    className={
                        "rounded-md border border-nb-gray-800 bg-nb-gray-920 px-4 py-3"
                    }
                >
                    <p className={"text-xs text-nb-gray-400 mb-2"}>
                        {uploaded && result.uploadedKey
                            ? "A local copy was also saved at:"
                            : "Bundle saved to:"}
                    </p>
                    <CopyableValue value={result.path} mono />
                    <p className={"text-xs text-nb-gray-500 mt-2"}>
                        You may need admin privileges to open this file.
                    </p>
                </div>
            )}
        </div>
    );
}

function CopyableValue({
    value,
    mono = false,
    large = false,
}: {
    value: string;
    mono?: boolean;
    large?: boolean;
}) {
    const [copied, setCopied] = useState(false);
    const onCopy = async () => {
        try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
        } catch {
            // ignore
        }
    };
    const onReveal = () => {
        void Browser.OpenURL(`file://${value}`).catch(() => {});
    };
    return (
        <div className={"flex items-center gap-2"}>
            <code
                className={cn(
                    "flex-1 min-w-0 truncate rounded bg-nb-gray-900 px-3 py-2 border border-nb-gray-800",
                    mono && "font-mono",
                    large ? "text-sm" : "text-xs",
                )}
            >
                {value}
            </code>
            <button
                type={"button"}
                onClick={onCopy}
                className={
                    "p-2 rounded-md border border-nb-gray-800 text-nb-gray-300 hover:text-white hover:bg-nb-gray-900"
                }
                aria-label={"Copy"}
            >
                {copied ? <Check size={14} /> : <Copy size={14} />}
            </button>
            {value.startsWith("/") || value.match(/^[A-Za-z]:\\/) ? (
                <button
                    type={"button"}
                    onClick={onReveal}
                    className={
                        "p-2 rounded-md border border-nb-gray-800 text-nb-gray-300 hover:text-white hover:bg-nb-gray-900"
                    }
                    aria-label={"Reveal"}
                >
                    <FolderOpen size={14} />
                </button>
            ) : null}
        </div>
    );
}

const LEGAL_LINKS: { label: string; url: string }[] = [
    { label: "Imprint", url: "https://netbird.io/imprint" },
    { label: "Privacy", url: "https://netbird.io/privacy" },
    { label: "CLA", url: "https://netbird.io/cla" },
    { label: "Terms of Service", url: "https://netbird.io/terms" },
];

function openUrl(url: string) {
    void Browser.OpenURL(url).catch(() => window.open(url, "_blank"));
}

function AboutSection() {
    const { status } = useStatus();
    const guiVersion = pkg.version;
    const daemonVersion = status?.daemonVersion ?? "—";

    const updateVersion = (status?.events ?? [])
        .map((e) => e.metadata?.["new_version_available"])
        .find((v): v is string => Boolean(v));

    const triggerUpdate = () => {
        UpdateSvc.Trigger().catch(() => {});
    };

    return (
        <div className={"flex flex-col gap-5 max-w-2xl"}>
            <div className={"flex gap-6 items-center"}>
                <img
                    src={netbirdAppIcon}
                    alt={"NetBird"}
                    className={
                        "w-24 h-24 rounded-2xl shrink-0 border border-nb-gray-800"
                    }
                />
                <div className={"flex-1 min-w-0 flex flex-col gap-2"}>
                    <h2 className={"text-2xl font-semibold"}>NetBird</h2>
                    <div className={"text-sm text-nb-gray-300 space-y-0.5"}>
                        <div>GUI v{guiVersion}</div>
                        <div>Client v{daemonVersion}</div>
                    </div>
                </div>
            </div>

            {updateVersion && (
                <div
                    className={
                        "flex items-center justify-between gap-4 rounded-md border border-nb-gray-800 bg-nb-gray-920 px-4 py-3"
                    }
                >
                    <div>
                        <p className={"text-sm font-medium"}>
                            Version {updateVersion} is available.
                        </p>
                        <button
                            type={"button"}
                            onClick={() =>
                                openUrl(
                                    `https://github.com/netbirdio/netbird/releases/tag/v${updateVersion}`,
                                )
                            }
                            className={"text-xs text-netbird hover:underline"}
                        >
                            What's new?
                        </button>
                    </div>
                    <Button
                        variant={"primary"}
                        size={"sm"}
                        onClick={triggerUpdate}
                    >
                        Restart now
                    </Button>
                </div>
            )}

            <p className={"text-xs text-nb-gray-500"}>
                © {new Date().getFullYear()} NetBird. All Rights Reserved.
            </p>
            <div
                className={
                    "flex flex-wrap gap-x-3 gap-y-1 text-xs text-nb-gray-400"
                }
            >
                {LEGAL_LINKS.map((link, i) => (
                    <span key={link.url} className={"flex items-center"}>
                        {i > 0 && (
                            <span
                                className={"mr-3 text-nb-gray-700"}
                                aria-hidden
                            >
                                ·
                            </span>
                        )}
                        <button
                            type={"button"}
                            onClick={() => openUrl(link.url)}
                            className={"hover:text-nb-gray-200 transition"}
                        >
                            {link.label}
                        </button>
                    </span>
                ))}
            </div>
        </div>
    );
}
