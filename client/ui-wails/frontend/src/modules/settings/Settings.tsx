import { useCallback, useEffect, useRef, useState } from "react";
import { Browser } from "@wailsio/runtime";
import {
    Settings as SettingsSvc,
    Profiles as ProfilesSvc,
    Update as UpdateSvc,
} from "../../../bindings/github.com/netbirdio/netbird/client/ui-wails/services";
import type { Config } from "../../../bindings/github.com/netbirdio/netbird/client/ui-wails/services/models.js";
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
import {
    SettingsNavigation,
    SettingsSection,
} from "@/modules/settings/SettingsNavigation.tsx";

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
    const [active, setActive] = useState<SettingsSection>("general");
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
        <div className={"wails-draggable flex flex-1 min-h-0 p-4 gap-4"}>
            <div className={"flex flex-col w-52 shrink-0 items-center"}>
                <SettingsNavigation active={active} onChange={setActive} />
            </div>
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
                            {active === "general" && (
                                <GeneralSection
                                    cfg={cfg}
                                    setField={setField}
                                    onSaveServer={saveNow}
                                />
                            )}
                            {active === "network" && (
                                <NetworkSection cfg={cfg} setField={setField} />
                            )}
                            {active === "security" && (
                                <SecuritySection
                                    cfg={cfg}
                                    setField={setField}
                                />
                            )}
                            {active === "ssh" && (
                                <SshSection cfg={cfg} setField={setField} />
                            )}
                            {active === "advanced" && (
                                <AdvancedSection
                                    cfg={cfg}
                                    setField={setField}
                                />
                            )}
                            {active === "troubleshooting" && (
                                <TroubleshootingSection />
                            )}
                            {active === "about" && <AboutSection />}
                        </div>
                    )}
                </div>
            </MainRightSide>
        </div>
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

function TroubleshootingSection() {
    return (
        <SectionGroup title={"Debug bundle"}>
            <p className={"text-sm text-nb-gray-400"}>
                Debug bundle creation is not yet wired up in this view.
            </p>
        </SectionGroup>
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
