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
                    label={"Lazy Connections"}
                    helpText={
                        "Instead of maintaining always-on connections, NetBird activates them on-demand based on activity or signaling."
                    }
                />
                <FancyToggleSwitch
                    value={config.networkMonitor}
                    onChange={(v) => setField("networkMonitor", v)}
                    label={"Reconnect on Network Change"}
                    helpText={
                        "Monitor the network and automatically reconnect on changes such as Wi-Fi switching, Ethernet changes, or resume from sleep."
                    }
                />
            </SectionGroup>

            <SectionGroup title={"Routing & DNS"}>
                <FancyToggleSwitch
                    value={!config.disableDns}
                    onChange={(v) => setField("disableDns", !v)}
                    label={"Enable DNS"}
                    helpText={"Apply NetBird-managed DNS settings to the host resolver."}
                />
                <FancyToggleSwitch
                    value={!config.disableClientRoutes}
                    onChange={(v) => setField("disableClientRoutes", !v)}
                    label={"Enable Client Routes"}
                    helpText={"Accept routes from other peers to reach their networks."}
                />
                <FancyToggleSwitch
                    value={!config.disableServerRoutes}
                    onChange={(v) => setField("disableServerRoutes", !v)}
                    label={"Enable Server Routes"}
                    helpText={"Advertise this host's local routes to other peers."}
                />
                <FancyToggleSwitch
                    value={!config.disableIpv6}
                    onChange={(v) => setField("disableIpv6", !v)}
                    label={"Enable IPv6"}
                    helpText={"Use IPv6 addressing for the NetBird overlay network."}
                />
            </SectionGroup>
        </>
    );
}
