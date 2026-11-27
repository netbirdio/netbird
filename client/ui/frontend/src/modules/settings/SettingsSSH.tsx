import { useTranslation } from "react-i18next";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { HelpText } from "@/components/typography/HelpText";
import { Input } from "@/components/inputs/Input";
import { Label } from "@/components/typography/Label";
import { cn } from "@/lib/cn";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useGuardedControl } from "@/modules/settings/PrivilegeGuard.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { useRestrictions } from "@/contexts/RestrictionsContext.tsx";
import type { Restrictions } from "@bindings/services/models.js";
import { type ChangeEvent, useEffect, useId, useState } from "react";

// sshTabHasControls reports whether the SSH tab has anything left to show once
// the MDM-managed controls are hidden.
export function sshTabHasControls(mdm: Restrictions["mdm"]): boolean {
    return (
        mdm.allowServerSSH == null ||
        !mdm.enableSSHRoot ||
        !mdm.enableSSHSFTP ||
        !mdm.enableSSHLocalPortForwarding ||
        !mdm.enableSSHRemotePortForwarding ||
        !mdm.disableSSHAuth ||
        !mdm.sshJWTCacheTTL
    );
}

export function SettingsSSH() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();
    const { mdm } = useRestrictions();
    const guarded = useGuardedControl();
    const isSSHServerEnabled = config.serverSshAllowed;

    const sshServer = guarded("serverSshAllowed", (p) => p.allowSshServer);
    const sshRoot = guarded("enableSshRoot", (p) => p.enableSshRoot);
    // Inverted control: the guarded direction is switching authentication off, so
    // it is the already-disabled state that is the one-way one.
    const sshAuth = guarded("disableSshAuth", (p) => p.disableSshAuth, true);
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
    const showServerSection = mdm.allowServerSSH == null;
    const showCapabilitiesSection = !(
        mdm.enableSSHRoot &&
        mdm.enableSSHSFTP &&
        mdm.enableSSHLocalPortForwarding &&
        mdm.enableSSHRemotePortForwarding
    );
    const showAuthenticationSection = !(mdm.disableSSHAuth && mdm.sshJWTCacheTTL);

    return (
        <>
            {showServerSection && (
                <SectionGroup title={t("settings.ssh.section.server")}>
                    <FancyToggleSwitch
                        value={config.serverSshAllowed}
                        onChange={sshServer.apply}
                        disabled={sshServer.disabled}
                        label={t("settings.ssh.server.label")}
                        helpText={t("settings.ssh.server.help")}
                    />
                    {sshServer.hint}
                </SectionGroup>
            )}

            {showCapabilitiesSection && (
                <SectionGroup
                    title={t("settings.ssh.section.capabilities")}
                    disabled={!isSSHServerEnabled}
                >
                    {!mdm.enableSSHRoot && (
                        <>
                            <FancyToggleSwitch
                                value={config.enableSshRoot}
                                onChange={sshRoot.apply}
                                disabled={sshRoot.disabled}
                                label={t("settings.ssh.root.label")}
                                helpText={t("settings.ssh.root.help")}
                            />
                            {sshRoot.hint}
                        </>
                    )}
                    {!mdm.enableSSHSFTP && (
                        <FancyToggleSwitch
                            value={config.enableSshSftp}
                            onChange={(v) => setField("enableSshSftp", v)}
                            label={t("settings.ssh.sftp.label")}
                            helpText={t("settings.ssh.sftp.help")}
                        />
                    )}
                    {!mdm.enableSSHLocalPortForwarding && (
                        <FancyToggleSwitch
                            value={config.enableSshLocalPortForwarding}
                            onChange={(v) => setField("enableSshLocalPortForwarding", v)}
                            label={t("settings.ssh.localForward.label")}
                            helpText={t("settings.ssh.localForward.help")}
                        />
                    )}
                    {!mdm.enableSSHRemotePortForwarding && (
                        <FancyToggleSwitch
                            value={config.enableSshRemotePortForwarding}
                            onChange={(v) => setField("enableSshRemotePortForwarding", v)}
                            label={t("settings.ssh.remoteForward.label")}
                            helpText={t("settings.ssh.remoteForward.help")}
                        />
                    )}
                </SectionGroup>
            )}

            {showAuthenticationSection && (
                <SectionGroup
                    title={t("settings.ssh.section.authentication")}
                    disabled={!isSSHServerEnabled}
                >
                    {!mdm.disableSSHAuth && (
                        <>
                            <FancyToggleSwitch
                                value={!config.disableSshAuth}
                                onChange={(v) => sshAuth.apply(!v)}
                                disabled={sshAuth.disabled}
                                label={t("settings.ssh.jwt.label")}
                                helpText={t("settings.ssh.jwt.help")}
                            />
                            {sshAuth.hint}
                        </>
                    )}
                    {!mdm.sshJWTCacheTTL && (
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
                    )}
                </SectionGroup>
            )}
        </>
    );
}
