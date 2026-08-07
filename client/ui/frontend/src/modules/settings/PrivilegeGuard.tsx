import { useTranslation } from "react-i18next";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { usePrivilege } from "@/hooks/usePrivilege.ts";
import { Privilege } from "@bindings/services/models.js";
import { type ReactNode } from "react";

export type GuardedControl = {
    disabled: boolean;
    hint: ReactNode;
};

// useGuardedControl returns a guard for the settings controls the daemon
// restricts to root/administrator: enabling a remote-access server, or removing
// one of its safeguards.
//
// The daemon restricts only the direction that hands out access from a process
// running as root. So for an unprivileged user a guarded control is either
// unavailable (it is off and only they could turn it on) or a one-way switch (it
// is on, they may turn it off, but not back on) — say which, either way.
//
// A null privilege means we could not determine it: leave the control alone
// rather than greying it out with nothing to explain why. The daemon enforces
// this regardless, and a rejected save reports its own guidance.
export const useGuardedControl = () => {
    const privilege = usePrivilege();

    return (
        guardedDirectionActive: boolean,
        command: (p: Privilege) => string,
        // inverted marks a control whose guarded direction is switching it off,
        // so the one-way warning has to read the other way round.
        inverted = false,
    ): GuardedControl => {
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
};

// PrivilegeHint explains what an unprivileged user can and cannot do with a
// guarded control, and offers the command that does it with the privileges the
// daemon requires. oneWay covers the control being in the guarded state already:
// switching it back is the part that needs privileges.
export function PrivilegeHint({
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
                    ? t("settings.privilege.hint", { actor })
                    : inverted
                      ? t("settings.privilege.oneWayInverted", { actor })
                      : t("settings.privilege.oneWay", { actor })}
            </span>
            <CopyToClipboard message={command} alwaysShowIcon wrap variant={"bright"}>
                <code className={"select-text break-all font-mono text-xs text-nb-gray-200"}>
                    {command}
                </code>
            </CopyToClipboard>
        </div>
    );
}
