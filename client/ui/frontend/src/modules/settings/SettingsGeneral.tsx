import { useEffect, useRef } from "react";
import { Button } from "@/components/Button";
import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { HelpText } from "@/components/HelpText";
import { Input } from "@/components/Input";
import { Label } from "@/components/Label";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/modules/settings/SettingsContext.tsx";
import { ManagementServerSwitch } from "@/modules/settings/ManagementServerSwitch.tsx";
import { ManagementMode, useManagementUrl } from "@/modules/settings/useManagementUrl.ts";

export function SettingsGeneral() {
    const { config, setField } = useSettings();
    const { mode, setMode, setUrl, displayUrl, showError, canSave, save } = useManagementUrl();

    const inputRef = useRef<HTMLInputElement>(null);
    const prevMode = useRef(mode);
    useEffect(() => {
        if (
            prevMode.current === ManagementMode.Cloud &&
            mode === ManagementMode.SelfHosted
        ) {
            inputRef.current?.focus();
        }
        prevMode.current = mode;
    }, [mode]);

    return (
        <>
            <SectionGroup title={"General"}>
                <FancyToggleSwitch
                    value={!config.disableAutoConnect}
                    onChange={(v) => setField("disableAutoConnect", !v)}
                    label={"Connect on Startup"}
                    helpText={"Automatically establish a connection when the service starts."}
                />
                <FancyToggleSwitch
                    value={!config.disableNotifications}
                    onChange={(v) => setField("disableNotifications", !v)}
                    label={"Desktop Notifications"}
                    helpText={"Show desktop notifications for new updates and connection events."}
                />
            </SectionGroup>

            <SectionGroup title={"Connection"}>
                <div>
                    <div className={"flex items-start gap-3"}>
                        <div className={"flex-1 min-w-0"}>
                            <Label as={"div"}>Management Server</Label>
                            <HelpText>
                                Connect to NetBird Cloud or your own self-hosted management server.
                                Changes will reconnect the client.
                            </HelpText>
                        </div>
                        <ManagementServerSwitch value={mode} onChange={setMode} />
                    </div>
                    {mode === ManagementMode.SelfHosted && (
                        <div className={"flex items-start gap-3 mt-2"}>
                            <Input
                                ref={inputRef}
                                value={displayUrl}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder={"https://netbird.selfhosted.com:443"}
                                error={
                                    showError
                                        ? "Please enter a valid URL, e.g., https://netbird.selfhosted.com:443"
                                        : undefined
                                }
                            />
                            <Button
                                variant={"primary"}
                                size={"md"}
                                disabled={!canSave}
                                onClick={() => save()}
                            >
                                Save
                            </Button>
                        </div>
                    )}
                </div>
            </SectionGroup>
        </>
    );
}
