import { Button } from "@/components/Button";
import { WindowManager } from "@bindings/services";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";

export function SettingsDevelopment() {
    return (
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
    );
}
