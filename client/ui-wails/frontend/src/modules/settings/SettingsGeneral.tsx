import { Button } from "@/components/Button";
import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { HelpText } from "@/components/HelpText";
import { Input } from "@/components/Input";
import { Label } from "@/components/Label";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/modules/settings/SettingsContext.tsx";

export function SettingsGeneral() {
    const { config, setField, saveNow } = useSettings();
    return (
        <>
            <SectionGroup title={"General"}>
                <FancyToggleSwitch
                    value={!config.disableAutoConnect}
                    onChange={(v) => setField("disableAutoConnect", !v)}
                    label={"Connect on startup"}
                    helpText={
                        "Automatically connect to NetBird when the app launches."
                    }
                />
                <FancyToggleSwitch
                    value={!config.disableNotifications}
                    onChange={(v) => setField("disableNotifications", !v)}
                    label={"Show notifications"}
                    helpText={
                        "Show desktop notifications for connection events and updates."
                    }
                />
            </SectionGroup>

            <SectionGroup title={"Connection"}>
                <div>
                    <Label as={"div"}>Management Server</Label>
                    <HelpText>
                        The NetBird management server this client connects to.
                        Saving will reconnect to apply the new server.
                    </HelpText>
                    <div className={"flex items-center gap-2"}>
                        <div className={"flex-1"}>
                            <Input
                                value={config.managementUrl}
                                onChange={(e) =>
                                    setField("managementUrl", e.target.value)
                                }
                            />
                        </div>
                        <Button
                            variant={"primary"}
                            size={"md"}
                            onClick={() => saveNow()}
                        >
                            Save
                        </Button>
                    </div>
                </div>
            </SectionGroup>
        </>
    );
}
