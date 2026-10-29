import { useCallback, useEffect, useMemo, useState } from "react";
import {
    Preferences,
    Profiles as ProfilesSvc,
    Settings as SettingsSvc,
    WindowManager,
} from "@bindings/services";
import { Restrictions, SetConfigParams } from "@bindings/services/models.js";
import { ConfirmDialog } from "@/components/dialog/ConfirmDialog";
import { useAutoSizeWindow } from "@/hooks/useAutoSizeWindow";
import { errorDialog, formatErrorMessage } from "@/lib/errors";
import i18next from "@/lib/i18n";
import { isNetbirdCloud } from "@/hooks/useManagementUrl";
import { WelcomeStepTray } from "./WelcomeStepTray";
import { WelcomeStepManagement } from "./WelcomeStepManagement";

const WINDOW_WIDTH = 360;

type WelcomeStep = "tray" | "management";

function shouldShowManagementStep(
    activeProfileId: string,
    email: string,
    managementUrl: string,
    managedManagementUrl: string,
): boolean {
    if (managedManagementUrl) return false;
    // The default profile's ID equals the literal "default", so this check
    // holds whether we pass an ID or the legacy name.
    if (activeProfileId !== "default") return false;
    if (email.trim() !== "") return false;
    return isNetbirdCloud(managementUrl);
}

type InitialState = {
    profileName: string;
    username: string;
    managementUrl: string;
    needsManagementStep: boolean;
};

export default function WelcomeDialog() {
    const [step, setStep] = useState<WelcomeStep>("tray");
    const [initial, setInitial] = useState<InitialState | null>(null);
    const [closing, setClosing] = useState(false);
    const contentRef = useAutoSizeWindow<HTMLDivElement>(WINDOW_WIDTH, initial !== null);

    useEffect(() => {
        let cancelled = false;
        (async () => {
            try {
                const [username, active] = await Promise.all([
                    ProfilesSvc.Username(),
                    ProfilesSvc.GetActive(),
                ]);
                const profileId = active.id || "default";
                const [config, list, restrictions] = await Promise.all([
                    SettingsSvc.GetConfig({ profileName: profileId, username }),
                    ProfilesSvc.List(username),
                    SettingsSvc.GetRestrictions().catch(() => new Restrictions()),
                ]);
                const profile = list.find((p) => p.id === profileId);
                const email = profile?.email ?? "";
                if (cancelled) return;
                setInitial({
                    profileName: profileId,
                    username,
                    managementUrl: config.managementUrl,
                    needsManagementStep: shouldShowManagementStep(
                        profileId,
                        email,
                        config.managementUrl,
                        restrictions.mdm.managementURL,
                    ),
                });
            } catch (e) {
                console.error("welcome: initial probe failed", e);
                if (cancelled) return;
                setInitial({
                    profileName: "default",
                    username: "",
                    managementUrl: "",
                    needsManagementStep: false,
                });
            }
        })();
        return () => {
            cancelled = true;
        };
    }, []);

    const finish = useCallback(async () => {
        if (closing) return;
        setClosing(true);
        try {
            await Preferences.SetOnboardingCompleted(true);
        } catch (e) {
            console.error("persist onboarding flag:", e);
        }
        try {
            await WindowManager.OpenMain();
        } catch (e) {
            console.error("open main window:", e);
        }
        try {
            await WindowManager.CloseWelcome();
        } catch (e) {
            console.error("close welcome window:", e);
        }
    }, [closing]);

    const handleTrayContinue = useCallback(async () => {
        if (initial?.needsManagementStep) {
            setStep("management");
        } else {
            await finish();
        }
    }, [initial, finish]);

    const handleManagementContinue = useCallback(
        async (url: string) => {
            if (!initial) return;
            try {
                // SetConfig is a partial update — undefined fields are preserved Go-side.
                await SettingsSvc.SetConfig(
                    new SetConfigParams({
                        profileName: initial.profileName,
                        username: initial.username,
                        managementUrl: url,
                    }),
                );
            } catch (e) {
                await errorDialog({
                    Title: i18next.t("settings.error.saveTitle"),
                    Message: formatErrorMessage(e),
                });
                throw e;
            }
            setInitial((s) => (s ? { ...s, managementUrl: url } : s));
            await finish();
        },
        [initial, finish],
    );

    const content = useMemo(() => {
        if (!initial) {
            return null;
        }
        switch (step) {
            case "tray":
                return <WelcomeStepTray onContinue={handleTrayContinue} />;
            case "management":
                return (
                    <WelcomeStepManagement
                        initialUrl={initial.managementUrl}
                        onContinue={handleManagementContinue}
                    />
                );
        }
    }, [initial, step, handleTrayContinue, handleManagementContinue]);

    return (
        <ConfirmDialog
            ref={contentRef}
            aria-labelledby={step === "tray" ? "nb-welcome-title" : "nb-welcome-management-title"}
        >
            {content}
        </ConfirmDialog>
    );
}
