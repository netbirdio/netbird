import { useEffect, useState } from "react";
import { Events } from "@wailsio/runtime";
import { Button } from "@/components/Button";
import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { WindowManager } from "@bindings/services";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";

// Cross-window dev override: ClientVersionContext in the main window
// listens for this and replaces daemon-reported update state with the
// toggle values. Resets when the Settings window closes (no persistence
// by design).
const EVENT_DEV_OVERRIDES = "netbird:dev:overrides";
const PREVIEW_VERSION = "0.65.0";

export function SettingsDevelopment() {
    const [updateAvailable, setUpdateAvailable] = useState(false);
    const [enforced, setEnforced] = useState(false);

    useEffect(() => {
        void Events.Emit(EVENT_DEV_OVERRIDES, {
            updateAvailable,
            enforced,
            version: PREVIEW_VERSION,
        });
    }, [updateAvailable, enforced]);

    return (
        <>
            <SectionGroup title={"Auto-update"}>
                <FancyToggleSwitch
                    value={updateAvailable}
                    onChange={setUpdateAvailable}
                    label={"Is update available"}
                    helpText={
                        "Force the UI to think a new version is available. Reflects in the About card and the header badge."
                    }
                />
                <FancyToggleSwitch
                    value={enforced}
                    onChange={setEnforced}
                    label={"Auto update enabled"}
                    helpText={
                        "Force the UI to think management has auto-update enabled. Switches the About card to “Install now”."
                    }
                />
                <div className={"flex flex-col gap-2 items-start pt-2"}>
                    <Button
                        variant={"secondary"}
                        onClick={() =>
                            WindowManager.OpenInstallProgress(PREVIEW_VERSION).catch(
                                console.error,
                            )
                        }
                    >
                        Show updating dialog
                    </Button>
                </div>
            </SectionGroup>

            <SectionGroup title={"Session windows"}>
                <div className={"flex flex-col gap-2 items-start"}>
                    <Button
                        variant={"secondary"}
                        onClick={() =>
                            WindowManager.OpenSessionExpired().catch(console.error)
                        }
                    >
                        Open “Session expired”
                    </Button>
                    <Button
                        variant={"secondary"}
                        onClick={() =>
                            WindowManager.OpenSessionAboutToExpire(336).catch(
                                console.error,
                            )
                        }
                    >
                        Open “About to expire” (5:36)
                    </Button>
                </div>
            </SectionGroup>
        </>
    );
}
