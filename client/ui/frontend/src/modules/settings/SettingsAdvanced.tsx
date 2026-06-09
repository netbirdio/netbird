import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { System } from "@wailsio/runtime";
import Button from "@/components/buttons/Button";
import { HelpText } from "@/components/typography/HelpText";
import { Input } from "@/components/inputs/Input";
import { Label } from "@/components/typography/Label";
import { SectionGroup, SettingsBottomBar } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";

// macOS daemon/CLI only accept utun<N> (Darwin parses digits as the utun unit); Linux caps at IFNAMSIZ-1 = 15 chars.
const IS_MAC = System.IsMac();
const INTERFACE_NAME_RE = IS_MAC ? /^utun\d+$/ : /^[A-Za-z0-9._-]{1,15}$/;
const INTERFACE_NAME_ERROR_KEY = IS_MAC
    ? "settings.advanced.interfaceName.errorMac"
    : "settings.advanced.interfaceName.error";
// Port 0 lets the daemon pick a random free port.
const PORT_MIN = 0;
const PORT_MAX = 65535;
// Mirrors client/iface/iface.go MinMTU / MaxMTU.
const MTU_MIN = 576;
const MTU_MAX = 8192;

export function SettingsAdvanced() {
    const { t } = useTranslation();
    const { config, saveFields } = useSettings();

    const [values, setValues] = useState({
        interfaceName: config.interfaceName,
        wireguardPort: config.wireguardPort,
        mtu: config.mtu,
        preSharedKey: config.preSharedKey,
    });
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        setValues({
            interfaceName: config.interfaceName,
            wireguardPort: config.wireguardPort,
            mtu: config.mtu,
            preSharedKey: config.preSharedKey,
        });
    }, [config.interfaceName, config.wireguardPort, config.mtu, config.preSharedKey]);

    const errors = useMemo(() => {
        const out: { interfaceName?: string; wireguardPort?: string; mtu?: string } = {};
        if (!INTERFACE_NAME_RE.test(values.interfaceName)) {
            out.interfaceName = t(INTERFACE_NAME_ERROR_KEY);
        }
        if (
            !Number.isInteger(values.wireguardPort) ||
            values.wireguardPort < PORT_MIN ||
            values.wireguardPort > PORT_MAX
        ) {
            out.wireguardPort = t("settings.advanced.port.error", {
                min: PORT_MIN,
                max: PORT_MAX,
            });
        }
        if (!Number.isInteger(values.mtu) || values.mtu < MTU_MIN || values.mtu > MTU_MAX) {
            out.mtu = t("settings.advanced.mtu.error", { min: MTU_MIN, max: MTU_MAX });
        }
        return out;
    }, [values.interfaceName, values.wireguardPort, values.mtu, t]);

    const hasErrors = Object.keys(errors).length > 0;
    const hasChanges =
        values.interfaceName !== config.interfaceName ||
        values.wireguardPort !== config.wireguardPort ||
        values.mtu !== config.mtu ||
        values.preSharedKey !== config.preSharedKey;

    const handleSave = async () => {
        if (!hasChanges || saving || hasErrors) return;
        setSaving(true);
        try {
            await saveFields(values);
        } finally {
            setSaving(false);
        }
    };

    return (
        <>
            <SectionGroup title={t("settings.advanced.section.interface")}>
                <Input
                    label={t("settings.advanced.interfaceName.label")}
                    value={values.interfaceName}
                    error={errors.interfaceName}
                    onChange={(e) => setValues((v) => ({ ...v, interfaceName: e.target.value }))}
                />
                <div className={"grid grid-cols-2 gap-4"}>
                    <div>
                        <Input
                            label={t("settings.advanced.port.label")}
                            type={"number"}
                            min={PORT_MIN}
                            max={PORT_MAX}
                            value={values.wireguardPort}
                            error={errors.wireguardPort}
                            onChange={(e) =>
                                setValues((v) => ({
                                    ...v,
                                    wireguardPort: Number(e.target.value),
                                }))
                            }
                        />
                        <HelpText className={"mt-1.5"}>{t("settings.advanced.port.help")}</HelpText>
                    </div>
                    <Input
                        label={t("settings.advanced.mtu.label")}
                        type={"number"}
                        min={MTU_MIN}
                        max={MTU_MAX}
                        value={values.mtu}
                        error={errors.mtu}
                        onChange={(e) => setValues((v) => ({ ...v, mtu: Number(e.target.value) }))}
                    />
                </div>
            </SectionGroup>

            <SectionGroup title={t("settings.advanced.section.security")}>
                <div>
                    <Label as={"div"}>{t("settings.advanced.psk.label")}</Label>
                    <HelpText>{t("settings.advanced.psk.help")}</HelpText>
                    <Input
                        type={"password"}
                        showPasswordToggle
                        placeholder={"kQv0qF3oQpJYdgD5mC9hL7sB2xZ8nT4eU6wY1aR3jK0="}
                        value={values.preSharedKey}
                        onChange={(e) => setValues((v) => ({ ...v, preSharedKey: e.target.value }))}
                    />
                </div>
            </SectionGroup>

            <SettingsBottomBar>
                <Button
                    variant={"primary"}
                    size={"md"}
                    disabled={!hasChanges || saving || hasErrors}
                    onClick={handleSave}
                >
                    {t("common.saveChanges")}
                </Button>
            </SettingsBottomBar>
        </>
    );
}
