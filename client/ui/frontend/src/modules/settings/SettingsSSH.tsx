import { useTranslation } from "react-i18next";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { HelpText } from "@/components/typography/HelpText";
import { Input } from "@/components/inputs/Input";
import { Label } from "@/components/typography/Label";
import { cn } from "@/lib/cn";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { usePrivilege } from "@/hooks/usePrivilege.ts";
import { Privilege } from "@bindings/services/models.js";
import { type ChangeEvent, type ReactNode, useEffect, useId, useState } from "react";

export function SettingsSSH() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();
    const privilege = usePrivilege();
    const isSSHServerEnabled = config.serverSshAllowed;

    // The daemon restricts only the direction that hands out shells from a process
    // running as root. So for an unprivileged user a guarded control is either
    // unavailable (it is off and only they could turn it on) or a one-way switch
    // (it is on, they may turn it off, but not back on) — say which, either way.
    //
    // A null privilege means we could not determine it: leave the control alone
    // rather than greying it out with nothing to explain why. The daemon enforces
    // this regardless, and a rejected save reports its own guidance.
    const guarded = (
        guardedDirectionActive: boolean,
        command: (p: Privilege) => string,
        // inverted marks a control whose guarded direction is switching it off, so
        // the one-way warning has to read the other way round.
        inverted = false,
    ) => {
        if (!privilege || privilege.privileged) {
            return { disabled: false, hint: undefined };
        }
        const hint = (
            <PrivilegeHint
                actor={privilege.actor}
                command={command(privilege)}
                oneWay={guardedDirectionActive}
                inverted={inverted}
            />
        );
        return { disabled: !guardedDirectionActive, hint };
    };

    const sshServer = guarded(config.serverSshAllowed, (p) => p.allowSshServer);
    const sshRoot = guarded(config.enableSshRoot, (p) => p.enableSshRoot);
    // Inverted control: the guarded direction is switching authentication off, so
    // it is the already-disabled state that is the one-way one.
    const sshAuth = guarded(config.disableSshAuth, (p) => p.disableSshAuth, true);
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
                    disabled={sshServer.disabled}
                    label={t("settings.ssh.server.label")}
                    helpText={t("settings.ssh.server.help")}
                />
                {sshServer.hint}
            </SectionGroup>

            <SectionGroup
                title={t("settings.ssh.section.capabilities")}
                disabled={!isSSHServerEnabled}
            >
                <FancyToggleSwitch
                    value={config.enableSshRoot}
                    onChange={(v) => setField("enableSshRoot", v)}
                    disabled={sshRoot.disabled}
                    label={t("settings.ssh.root.label")}
                    helpText={t("settings.ssh.root.help")}
                />
                {sshRoot.hint}
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
                    disabled={sshAuth.disabled}
                    label={t("settings.ssh.jwt.label")}
                    helpText={t("settings.ssh.jwt.help")}
                />
                {sshAuth.hint}
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

// PrivilegeHint explains what an unprivileged user can and cannot do with a
// guarded control, and offers the command that does it with the privileges the
// daemon requires. oneWay covers the control being in the guarded state already:
// switching it back is the part that needs privileges.
function PrivilegeHint({
    actor,
    command,
    oneWay,
    inverted,
}: {
    actor: string;
    command: string;
    oneWay: boolean;
    inverted: boolean;
}): ReactNode {
    const { t } = useTranslation();
    if (!command) return null;
    return (
        <div
            className={
                "-mt-2 flex flex-col gap-1 rounded-md bg-nb-gray-930 px-3 py-2 text-xs text-nb-gray-300"
            }
        >
            <span>
                {!oneWay
                    ? t("settings.ssh.privilege.hint", { actor })
                    : inverted
                      ? t("settings.ssh.privilege.oneWayInverted", { actor })
                      : t("settings.ssh.privilege.oneWay", { actor })}
            </span>
            <CopyToClipboard message={command} alwaysShowIcon wrap variant={"bright"}>
                <code className={"select-text break-all font-mono text-xs text-nb-gray-200"}>
                    {command}
                </code>
            </CopyToClipboard>
        </div>
    );
}
