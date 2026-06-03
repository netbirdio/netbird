import { useCallback, useEffect, useMemo, useState } from "react";
import {
    Preferences,
    Profiles as ProfilesSvc,
    Settings as SettingsSvc,
    WindowManager,
} from "@bindings/services";
import { SetConfigParams } from "@bindings/services/models.js";
import { ConfirmDialog } from "@/components/dialog/ConfirmDialog";
import { useAutoSizeWindow } from "@/hooks/useAutoSizeWindow";
import { errorDialog } from "@/lib/dialogs";
import { formatErrorMessage } from "@/lib/errors";
import i18next from "@/lib/i18n";
import { isCloudManagementUrl } from "@/hooks/useManagementUrl";
import { WelcomeStepTray } from "./WelcomeStepTray";
import { WelcomeStepManagement } from "./WelcomeStepManagement";

const WINDOW_WIDTH = 360;

// WelcomeStep is the orchestrator's state machine. The transitions:
//   tray → management (if eligible) → finish
//   tray → finish (otherwise)
// Login itself is no longer part of onboarding — once the welcome window
// closes the user lands in the main window and clicks Connect there.
type WelcomeStep = "tray" | "management";

// shouldShowManagementStep asks the user about Cloud vs self-hosted only
// on a pristine setup — default profile, no email recorded (no successful
// login yet), and the management URL is either unset or already the cloud
// default. Any other state means the user (or a previous run) already
// made a deliberate choice and we shouldn't second-guess it.
function shouldShowManagementStep(
    activeProfile: string,
    email: string,
    managementUrl: string,
): boolean {
    if (activeProfile !== "default") return false;
    if (email.trim() !== "") return false;
    return isCloudManagementUrl(managementUrl);
}

// initial flow snapshot resolved at mount. Held in component state so the
// step-2 management input can hydrate from initialUrl, and so the
// "should we even show step 2" check is computed once (the user can't
// change profile / URL from inside the welcome window).
type InitialState = {
    profileName: string;
    username: string;
    managementUrl: string;
    needsManagementStep: boolean;
};

export default function WelcomeDialog() {
    const contentRef = useAutoSizeWindow<HTMLDivElement>(WINDOW_WIDTH);
    const [step, setStep] = useState<WelcomeStep>("tray");
    const [initial, setInitial] = useState<InitialState | null>(null);
    const [closing, setClosing] = useState(false);

    // Probe daemon state on mount: who's the active profile, do they
    // have an email recorded, and what management URL is configured?
    // Errors fall through to "skip the management step" so a daemon
    // hiccup never blocks onboarding entirely.
    useEffect(() => {
        let cancelled = false;
        (async () => {
            try {
                // Resolve username + active profile first so GetConfig + List
                // can target the actual profile (passing empty strings would
                // work today since the daemon falls back to the default
                // profile, but being explicit shields us from future
                // changes to that fallback).
                const [username, active] = await Promise.all([
                    ProfilesSvc.Username(),
                    ProfilesSvc.GetActive(),
                ]);
                const profileName = active.profileName || "default";
                const [config, list] = await Promise.all([
                    SettingsSvc.GetConfig({ profileName, username }),
                    ProfilesSvc.List(username),
                ]);
                const profile = list.find((p) => p.name === profileName);
                const email = profile?.email ?? "";
                if (cancelled) return;
                setInitial({
                    profileName,
                    username,
                    managementUrl: config.managementUrl,
                    needsManagementStep: shouldShowManagementStep(
                        profileName,
                        email,
                        config.managementUrl,
                    ),
                });
            } catch (e) {
                console.error("welcome: initial probe failed", e);
                if (cancelled) return;
                // Conservative fallback: skip the management step rather
                // than block onboarding behind a daemon hiccup.
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

    // finish persists the onboarding flag, opens the main window so the
    // user has somewhere to land, and closes the welcome window. Called
    // at the end of every successful flow (tray-only and tray→management
    // alike). The Connect button in the main window picks up from here.
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
                // SetConfig is a partial update — pointer fields left
                // undefined are preserved (services/settings.go). We only
                // touch managementUrl; adminUrl stays empty here because
                // the daemon already has its own value loaded.
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
            // Probe in flight — render an empty container so the dialog
            // window measures something tiny instead of flashing the
            // tray step before we know whether step 2 applies. The probe
            // completes within a single tick on a healthy daemon.
            return <div className={"h-32"} />;
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

    return <ConfirmDialog ref={contentRef}>{content}</ConfirmDialog>;
}
