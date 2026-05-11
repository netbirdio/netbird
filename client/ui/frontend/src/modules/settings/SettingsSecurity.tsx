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
                    label={"Block Inbound Traffic"}
                    helpText={
                        "Reject unsolicited connections from peers to this device and any networks it routes. Outbound traffic is unaffected."
                    }
                />
                <FancyToggleSwitch
                    value={config.blockLanAccess}
                    onChange={(v) => setField("blockLanAccess", v)}
                    label={"Block LAN Access"}
                    helpText={
                        "Prevent peers from reaching your local network or its devices when this device routes their traffic."
                    }
                />
            </SectionGroup>

            <SectionGroup title={"Encryption"}>
                <FancyToggleSwitch
                    value={config.rosenpassEnabled}
                    onChange={(v) => {
                        setField("rosenpassEnabled", v);
                        if (!v) setField("rosenpassPermissive", false);
                    }}
                    label={"Enable Quantum-Resistance"}
                    helpText={
                        "Add a post-quantum key exchange via Rosenpass on top of WireGuard®."
                    }
                />
                <FancyToggleSwitch
                    value={config.rosenpassPermissive}
                    onChange={(v) => setField("rosenpassPermissive", v)}
                    label={"Enable Permissive Mode"}
                    helpText={
                        "Allow connections to peers without quantum-resistance support."
                    }
                    disabled={!config.rosenpassEnabled}
                />
            </SectionGroup>
        </>
    );
}
