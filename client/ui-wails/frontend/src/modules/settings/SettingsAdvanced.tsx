import { useState } from "react";
import Button from "@/components/Button";
import { HelpText } from "@/components/HelpText";
import { Input } from "@/components/Input";
import { Label } from "@/components/Label";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/modules/settings/SettingsContext.tsx";

export function SettingsAdvanced() {
    const { config, saveFields } = useSettings();

    const [values, setValues] = useState({
        interfaceName: config.interfaceName,
        wireguardPort: config.wireguardPort,
        mtu: config.mtu,
        preSharedKey: config.preSharedKey,
    });
    const [saving, setSaving] = useState(false);

    const hasChanges =
        values.interfaceName !== config.interfaceName ||
        values.wireguardPort !== config.wireguardPort ||
        values.mtu !== config.mtu ||
        values.preSharedKey !== config.preSharedKey;

    const handleSave = async () => {
        if (!hasChanges || saving) return;
        setSaving(true);
        try {
            await saveFields(values);
        } finally {
            setSaving(false);
        }
    };

    return (
        <>
            <SectionGroup title={"Interface"}>
                <Input
                    label={"Name"}
                    value={values.interfaceName}
                    onChange={(e) =>
                        setValues((v) => ({ ...v, interfaceName: e.target.value }))
                    }
                />
                <div className={"grid grid-cols-2 gap-4"}>
                    <Input
                        label={"Port"}
                        type={"number"}
                        value={values.wireguardPort}
                        onChange={(e) =>
                            setValues((v) => ({
                                ...v,
                                wireguardPort: Number(e.target.value),
                            }))
                        }
                    />
                    <Input
                        label={"MTU"}
                        type={"number"}
                        value={values.mtu}
                        onChange={(e) =>
                            setValues((v) => ({ ...v, mtu: Number(e.target.value) }))
                        }
                    />
                </div>
            </SectionGroup>

            <SectionGroup title={"Security"}>
                <div>
                    <Label as={"div"}>Pre-shared Key</Label>
                    <HelpText>
                        Optional WireGuard PSK for extra symmetric encryption. Not the same as a
                        NetBird Setup Key. You will only communicate with peers that use the same
                        pre-shared key.
                    </HelpText>
                    <Input
                        type={"password"}
                        showPasswordToggle
                        placeholder={"kQv0qF3oQpJYdgD5mC9hL7sB2xZ8nT4eU6wY1aR3jK0="}
                        value={values.preSharedKey}
                        onChange={(e) =>
                            setValues((v) => ({ ...v, preSharedKey: e.target.value }))
                        }
                    />
                </div>
            </SectionGroup>

            <div className={"absolute bottom-0 left-0 w-full"}>
                <div className={"w-full flex justify-end px-8 py-5 border-t border-nb-gray-910"}>
                    <Button
                        variant={"primary"}
                        size={"md"}
                        disabled={!hasChanges || saving}
                        onClick={handleSave}
                    >
                        Save Changes
                    </Button>
                </div>
            </div>
        </>
    );
}
