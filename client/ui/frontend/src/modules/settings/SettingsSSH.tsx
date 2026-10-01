import { type TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { HelpText } from "@/components/typography/HelpText";
import { Input } from "@/components/inputs/Input";
import { Label } from "@/components/typography/Label";
import { cn } from "@/lib/cn";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { type GuardedField, useSettings } from "@/contexts/SettingsContext.tsx";
import { usePrivilege } from "@/hooks/usePrivilege.ts";
import type { Privilege } from "@bindings/services/models.js";
import { type ChangeEvent, type ReactNode, useEffect, useId, useState } from "react";

export function SettingsSSH() {
    const { t } = useTranslation();
    const { config, setField, saveGuardedField } = useSettings();
    const privilege = usePrivilege();
    // The field whose elevation prompt is currently up, if any. The prompt is
    // modal to the operating system, not to us, so the guarded controls are held
    // still meanwhile rather than allowed to stack a second one behind it.
    const [authorizing, setAuthorizing] = useState<GuardedField | null>(null);
    const isSSHServerEnabled = config.serverSshAllowed;

    const authorize = async (field: GuardedField, value: boolean) => {
        setAuthorizing(field);
        try {
            await saveGuardedField(field, value);
        } finally {
            setAuthorizing(null);
        }
    };

    // The daemon restricts only the direction that hands out shells from a process
    // running as root: for all three settings that is switching the field on.
    //
    // An unprivileged user gets that direction routed through the platform's
    // elevation prompt where there is one to raise, and otherwise the old
    // arrangement, where the control is either unavailable (it is off and only a
    // privileged caller could turn it on) or a one-way switch (it is on, they may
    // turn it off but not back on) with the command that does it.
    //
    // A null privilege means we could not determine it: leave the control alone
    // rather than greying it out with nothing to explain why. The daemon enforces
    // this regardless, and a rejected save reports its own guidance.
    const guarded = (
        field: GuardedField,
        command: (p: Privilege) => string,
        // inverted marks a control whose guarded direction is switching it off, so
        // the one-way warning has to read the other way round.
        inverted = false,
    ) => {
        const plain = (value: boolean) => setField(field, value);
        if (!privilege || privilege.privileged) {
            return { apply: plain, disabled: false, hint: undefined };
        }

        const guardedDirectionActive = config[field];
        const hint = (pending: boolean, command?: string) => (
            <GuardedHint
                actor={actorLabel(privilege, t)}
                oneWay={guardedDirectionActive}
                inverted={inverted}
                pending={pending}
                command={command}
            />
        );

        if (privilege.canElevate) {
            return {
                // Switching off is ours to do; only switching on is authorized.
                apply: (value: boolean) => {
                    if (!value) {
                        plain(value);
                        return;
                    }
                    void authorize(field, value);
                },
                disabled: authorizing !== null,
                hint: hint(authorizing === field),
            };
        }
        return {
            apply: plain,
            disabled: !guardedDirectionActive,
            hint: hint(false, command(privilege)),
        };
    };

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
    return (
        <>
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

            <SectionGroup
                title={t("settings.ssh.section.capabilities")}
                disabled={!isSSHServerEnabled}
            >
                <FancyToggleSwitch
                    value={config.enableSshRoot}
                    onChange={sshRoot.apply}
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
                    onChange={(v) => sshAuth.apply(!v)}
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

// actorLabel names the principal the daemon requires, in the user's language. The
// Go side reports which one it is rather than wording it, because "administrator
// privileges" is English and a translated sentence cannot borrow it.
function actorLabel(privilege: Privilege, t: TFunction): string {
    return privilege.actorKey === "administrator"
        ? t("settings.ssh.privilege.actorAdministrator")
        : t("settings.ssh.privilege.actorRoot");
}

// GuardedHint is what a control the daemon guards says to an unprivileged user.
// There are three things worth saying, and it says at most one:
//
//   - A prompt is open. Worth a line because it can take a few seconds to appear,
//     long enough that a control which merely went inert would read as a hang.
//   - The setting is in its guarded state already (oneWay), so the user may switch
//     it back as they please and it is switching it away again that will ask. No
//     command either way: the direction they can take is theirs to take.
//   - Only a privileged caller can move it at all, and there is no prompt to
//     raise: the command that does it belongs here, and nothing else will do.
//
// Which leaves the case of a control whose guarded direction is still ahead of the
// user and a prompt that can be raised for it: nothing to say, because clicking it
// raises the prompt and the prompt explains itself.
function GuardedHint({
    actor,
    oneWay,
    inverted,
    pending,
    command,
}: {
    actor: string;
    oneWay: boolean;
    inverted: boolean;
    pending: boolean;
    command?: string;
}): ReactNode {
    const { t } = useTranslation();

    if (pending) {
        return <HintBox>{t("settings.ssh.privilege.authorizePending")}</HintBox>;
    }
    if (oneWay) {
        return (
            <HintBox>
                <span>
                    {inverted
                        ? t("settings.ssh.privilege.oneWayInverted", { actor })
                        : t("settings.ssh.privilege.oneWay", { actor })}
                </span>
            </HintBox>
        );
    }
    if (!command) return null;
    return (
        <HintBox>
            <span>{t("settings.ssh.privilege.hint", { actor })}</span>
            <CopyToClipboard message={command} alwaysShowIcon wrap variant={"bright"}>
                <code className={"select-text break-all font-mono text-xs text-nb-gray-200"}>
                    {command}
                </code>
            </CopyToClipboard>
        </HintBox>
    );
}

// HintBox is the box a guarded control puts its explanation in, directly under the
// control it belongs to.
function HintBox({ children }: { children: ReactNode }): ReactNode {
    return (
        <div
            className={
                "-mt-2 flex flex-col gap-1 rounded-md bg-nb-gray-930 px-3 py-2 text-xs text-nb-gray-300"
            }
        >
            {children}
        </div>
    );
}
