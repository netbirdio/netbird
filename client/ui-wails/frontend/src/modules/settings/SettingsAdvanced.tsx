import { useEffect, useState } from "react";
import Button from "@/components/Button";
import { HelpText } from "@/components/HelpText";
import { Input } from "@/components/Input";
import { Label } from "@/components/Label";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/modules/settings/SettingsContext.tsx";

export function SettingsAdvanced() {
    const { config, saveFields } = useSettings();

    const [draft, setDraft] = useState({
        interfaceName: config.interfaceName,
        wireguardPort: config.wireguardPort,
        mtu: config.mtu,
        preSharedKey: config.preSharedKey,
    });
    const [saving, setSaving] = useState(false);

    // Re-sync the draft when the underlying config changes from elsewhere (e.g. reload).
    useEffect(() => {
        setDraft({
            interfaceName: config.interfaceName,
            wireguardPort: config.wireguardPort,
            mtu: config.mtu,
            preSharedKey: config.preSharedKey,
        });
    }, [config.interfaceName, config.wireguardPort, config.mtu, config.preSharedKey]);

    const isDirty =
        draft.interfaceName !== config.interfaceName ||
        draft.wireguardPort !== config.wireguardPort ||
        draft.mtu !== config.mtu ||
        draft.preSharedKey !== config.preSharedKey;

    const handleSave = async () => {
        if (!isDirty || saving) return;
        setSaving(true);
        try {
            await saveFields(draft);
        } finally {
            setSaving(false);
        }
    };

    return (
        <>
            <SectionGroup title={"Interface"}>
                <Input
                    label={"Name"}
                    value={draft.interfaceName}
                    onChange={(e) => setDraft((d) => ({ ...d, interfaceName: e.target.value }))}
                />
                <div className={"grid grid-cols-2 gap-4"}>
                    <Input
                        label={"Port"}
                        type={"number"}
                        value={draft.wireguardPort}
                        onChange={(e) =>
                            setDraft((d) => ({
                                ...d,
                                wireguardPort: Number(e.target.value),
                            }))
                        }
                    />
                    <Input
                        label={"MTU"}
                        type={"number"}
                        value={draft.mtu}
                        onChange={(e) =>
                            setDraft((d) => ({
                                ...d,
                                mtu: Number(e.target.value),
                            }))
                        }
                    />
                </div>
            </SectionGroup>

            <SectionGroup title={"Security"}>
                <div>
                    <Label as={"div"}>Pre-shared Key</Label>
                    <HelpText>
                        Optional WireGuard PSK for extra symmetric encryption. Not the same as a
                        NetBird Setup Key. Set the same value on every peer, otherwise they can't
                        connect to each other.
                    </HelpText>
                    <Input
                        type={"password"}
                        showPasswordToggle
                        placeholder={"kQv0qF3oQpJYdgD5mC9hL7sB2xZ8nT4eU6wY1aR3jK0="}
                        value={draft.preSharedKey}
                        onChange={(e) =>
                            setDraft((d) => ({
                                ...d,
                                preSharedKey: e.target.value,
                            }))
                        }
                    />
                </div>
            </SectionGroup>

            <div className={"absolute bottom-0 left-0 w-full"}>
                <div className={"w-full flex justify-end px-8 py-5 border-t border-nb-gray-910"}>
                    <Button
                        variant={"primary"}
                        size={"md"}
                        disabled={!isDirty || saving}
                        onClick={handleSave}
                    >
                        Save Changes
                    </Button>
                </div>
            </div>
        </>
    );
}
