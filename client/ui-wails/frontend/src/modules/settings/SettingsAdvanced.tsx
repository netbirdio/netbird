import { HelpText } from "@/components/HelpText";
import { Input } from "@/components/Input";
import { Label } from "@/components/Label";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/modules/settings/SettingsContext.tsx";

export function SettingsAdvanced() {
    const { config, setField } = useSettings();
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
                        value={config.preSharedKey}
                        onChange={(e) =>
                            setField("preSharedKey", e.target.value)
                        }
                    />
                </div>
            </SectionGroup>

            <SectionGroup title={"Interface"}>
                <Input
                    label={"Name"}
                    value={config.interfaceName}
                    onChange={(e) => setField("interfaceName", e.target.value)}
                />
                <div className={"grid grid-cols-2 gap-4"}>
                    <Input
                        label={"WireGuard Port"}
                        type={"number"}
                        value={config.wireguardPort}
                        onChange={(e) =>
                            setField("wireguardPort", Number(e.target.value))
                        }
                    />
                    <Input
                        label={"MTU"}
                        type={"number"}
                        value={config.mtu}
                        onChange={(e) =>
                            setField("mtu", Number(e.target.value))
                        }
                    />
                </div>
            </SectionGroup>
        </>
    );
}
