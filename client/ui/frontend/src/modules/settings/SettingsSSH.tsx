import { useTranslation } from "react-i18next";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { HelpText } from "@/components/typography/HelpText";
import { Input } from "@/components/inputs/Input";
import { Label } from "@/components/typography/Label";
import { cn } from "@/lib/cn";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { type ChangeEvent, useEffect, useId, useState } from "react";

export function SettingsSSH() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();
    const isSSHServerEnabled = config.serverSshAllowed;
    const jwtTtlId = useId();
    const [jwtTtlInput, setJwtTtlInput] = useState(String(config.sshJwtCacheTtl));

    useEffect(() => {
        setJwtTtlInput(String(config.sshJwtCacheTtl));
    }, [config.sshJwtCacheTtl]);

    const handleJwtTtlChange = (e: ChangeEvent<HTMLInputElement>) => {
        const v = e.target.value;
        setJwtTtlInput(v);
        if (v === "") return;
        const n = Number(v);
        if (Number.isFinite(n) && n >= 0) {
            setField("sshJwtCacheTtl", n);
        }
    };

    const handleJwtTtlBlur = () => {
        if (jwtTtlInput === "") {
            setJwtTtlInput("0");
            setField("sshJwtCacheTtl", 0);
            return;
        }
        const n = Number(jwtTtlInput);
        if (!Number.isFinite(n) || n < 0) {
            setJwtTtlInput(String(config.sshJwtCacheTtl));
        }
    };
    return (
        <>
            <SectionGroup title={t("settings.ssh.section.server")}>
                <FancyToggleSwitch
                    value={config.serverSshAllowed}
                    onChange={(v) => setField("serverSshAllowed", v)}
                    label={t("settings.ssh.server.label")}
                    helpText={t("settings.ssh.server.help")}
                />
            </SectionGroup>

            <SectionGroup
                title={t("settings.ssh.section.capabilities")}
                disabled={!isSSHServerEnabled}
            >
                <FancyToggleSwitch
                    value={config.enableSshRoot}
                    onChange={(v) => setField("enableSshRoot", v)}
                    label={t("settings.ssh.root.label")}
                    helpText={t("settings.ssh.root.help")}
                />
                <FancyToggleSwitch
                    value={config.enableSshSftp}
                    onChange={(v) => setField("enableSshSftp", v)}
                    label={t("settings.ssh.sftp.label")}
                    helpText={t("settings.ssh.sftp.help")}
                />
                <FancyToggleSwitch
                    value={config.enableSshLocalPortForwarding}
                    onChange={(v) => setField("enableSshLocalPortForwarding", v)}
                    label={t("settings.ssh.localForward.label")}
                    helpText={t("settings.ssh.localForward.help")}
                />
                <FancyToggleSwitch
                    value={config.enableSshRemotePortForwarding}
                    onChange={(v) => setField("enableSshRemotePortForwarding", v)}
                    label={t("settings.ssh.remoteForward.label")}
                    helpText={t("settings.ssh.remoteForward.help")}
                />
            </SectionGroup>

            <SectionGroup
                title={t("settings.ssh.section.authentication")}
                disabled={!isSSHServerEnabled}
            >
                <FancyToggleSwitch
                    value={!config.disableSshAuth}
                    onChange={(v) => setField("disableSshAuth", !v)}
                    label={t("settings.ssh.jwt.label")}
                    helpText={t("settings.ssh.jwt.help")}
                />
                <div
                    className={cn(
                        "flex items-center justify-between gap-6",
                        config.disableSshAuth && "pointer-events-none opacity-50",
                    )}
                >
                    <div className={"max-w-md flex-1"}>
                        <Label htmlFor={jwtTtlId}>{t("settings.ssh.jwtTtl.label")}</Label>
                        <HelpText margin={false}>{t("settings.ssh.jwtTtl.help")}</HelpText>
                    </div>
                    <div className={"w-40 shrink-0"}>
                        <Input
                            id={jwtTtlId}
                            type={"number"}
                            min={0}
                            value={jwtTtlInput}
                            onChange={handleJwtTtlChange}
                            onBlur={handleJwtTtlBlur}
                            customSuffix={t("settings.ssh.jwtTtl.suffix")}
                        />
                    </div>
                </div>
            </SectionGroup>
        </>
    );
}
