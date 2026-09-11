import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { System } from "@wailsio/runtime";
import Button from "@/components/buttons/Button";
import { HelpText } from "@/components/typography/HelpText";
import { Input } from "@/components/inputs/Input";
import { Label } from "@/components/typography/Label";
import { SectionGroup, SettingsBottomBar } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { useRestrictions } from "@/contexts/RestrictionsContext.tsx";

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

const PSK_MASK = "**********";

export function SettingsAdvanced() {
    const { t } = useTranslation();
    const { config, saveFields } = useSettings();
    const { mdm } = useRestrictions();

    const initialPsk = config.preSharedKeySet ? PSK_MASK : "";

    const [values, setValues] = useState({
        interfaceName: config.interfaceName,
        wireguardPort: config.wireguardPort,
        mtu: config.mtu,
    });

    const [pskInputValue, setPskInputValue] = useState(initialPsk);
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        setValues({
            interfaceName: config.interfaceName,
            wireguardPort: config.wireguardPort,
            mtu: config.mtu,
        });
        setPskInputValue(config.preSharedKeySet ? PSK_MASK : "");
    }, [config.interfaceName, config.wireguardPort, config.mtu, config.preSharedKeySet]);

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

    const filteredErrors = mdm.wireguardPort ? { ...errors, wireguardPort: undefined } : errors;
    const hasErrors = Object.values(filteredErrors).some((v) => v !== undefined);
    const pskChanged = pskInputValue !== initialPsk;
    const hasChanges =
        values.interfaceName !== config.interfaceName ||
        (!mdm.wireguardPort && values.wireguardPort !== config.wireguardPort) ||
        values.mtu !== config.mtu ||
        (!mdm.preSharedKey && pskChanged);

    const handleSave = async () => {
        if (!hasChanges || saving || hasErrors) return;
        setSaving(true);
        try {
            const partial: typeof values = { ...values };
            if (mdm.wireguardPort) partial.wireguardPort = config.wireguardPort;

            const pskEdited = !mdm.preSharedKey && pskChanged && pskInputValue !== PSK_MASK;
            const pskOpts = pskEdited ? { preSharedKey: pskInputValue } : undefined;
            await saveFields(partial, pskOpts);
            if (pskEdited) setPskInputValue(pskInputValue === "" ? "" : PSK_MASK);
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
                    spellCheck={false}
                    autoComplete={"off"}
                    autoCorrect={"off"}
                    autoCapitalize={"off"}
                />
                <div className={mdm.wireguardPort ? "" : "grid grid-cols-2 gap-4"}>
                    {!mdm.wireguardPort && (
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
                            <HelpText className={"mt-1.5"}>
                                {t("settings.advanced.port.help")}
                            </HelpText>
                        </div>
                    )}
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

            {!mdm.preSharedKey && (
                <SectionGroup title={t("settings.advanced.section.security")}>
                    <div>
                        <Label as={"div"}>{t("settings.advanced.psk.label")}</Label>
                        <HelpText>{t("settings.advanced.psk.help")}</HelpText>
                        <Input
                            type={"password"}
                            showPasswordToggle={pskInputValue !== PSK_MASK}
                            placeholder={"kQv0qF3oQpJYdgD5mC9hL7sB2xZ8nT4eU6wY1aR3jK0="}
                            value={pskInputValue}
                            onChange={(e) => setPskInputValue(e.target.value)}
                            spellCheck={false}
                            autoComplete={"new-password"}
                            autoCorrect={"off"}
                            autoCapitalize={"off"}
                        />
                    </div>
                </SectionGroup>
            )}

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
