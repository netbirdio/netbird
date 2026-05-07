import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/modules/settings/SettingsContext.tsx";

export function SettingsSecurity() {
    const { config, setField } = useSettings();
    return (
        <>
            <SectionGroup title={"Firewall"}>
                <FancyToggleSwitch
                    value={config.blockInbound}
                    onChange={(v) => setField("blockInbound", v)}
                    label={"Block inbound traffic"}
                    helpText={
                        "Drop all unsolicited inbound traffic on the NetBird interface."
                    }
                />
                <FancyToggleSwitch
                    value={config.blockLanAccess}
                    onChange={(v) => setField("blockLanAccess", v)}
                    label={"Block LAN access"}
                    helpText={
                        "Prevent peers from reaching this host's local network."
                    }
                />
            </SectionGroup>

            <SectionGroup title={"Encryption"}>
                <FancyToggleSwitch
                    value={config.rosenpassEnabled}
                    onChange={(v) => setField("rosenpassEnabled", v)}
                    label={"Quantum-resistant encryption"}
                    helpText={
                        "Add a post-quantum key exchange (Rosenpass) on top of WireGuard."
                    }
                >
                    <FancyToggleSwitch
                        value={config.rosenpassPermissive}
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
