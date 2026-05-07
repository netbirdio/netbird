import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/modules/settings/SettingsContext.tsx";

export function SettingsNetwork() {
    const { config, setField } = useSettings();
    return (
        <>
            <SectionGroup title={"Connectivity"}>
                <FancyToggleSwitch
                    value={config.lazyConnectionEnabled}
                    onChange={(v) => setField("lazyConnectionEnabled", v)}
                    label={"Lazy connections"}
                    helpText={
                        "Only establish peer tunnels on first traffic instead of eagerly at startup."
                    }
                />
                <FancyToggleSwitch
                    value={config.networkMonitor}
                    onChange={(v) => setField("networkMonitor", v)}
                    label={"Network monitor"}
                    helpText={
                        "Reconnect automatically when the host network changes (Wi-Fi switch, VPN, sleep/wake)."
                    }
                />
            </SectionGroup>

            <SectionGroup title={"Routing & DNS"}>
                <FancyToggleSwitch
                    value={!config.disableDns}
                    onChange={(v) => setField("disableDns", !v)}
                    label={"Enable DNS"}
                    helpText={
                        "Apply NetBird-managed DNS settings to the host resolver."
                    }
                />
                <FancyToggleSwitch
                    value={!config.disableClientRoutes}
                    onChange={(v) => setField("disableClientRoutes", !v)}
                    label={"Enable client routes"}
                    helpText={
                        "Accept routes advertised by other peers so this client can reach their networks."
                    }
                />
                <FancyToggleSwitch
                    value={!config.disableServerRoutes}
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
