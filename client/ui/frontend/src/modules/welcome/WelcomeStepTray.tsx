import { useTranslation } from "react-i18next";
import { Button } from "@/components/buttons/Button";
import { DialogActions } from "@/components/dialog/DialogActions";
import { DialogDescription } from "@/components/dialog/DialogDescription";
import { DialogHeading } from "@/components/dialog/DialogHeading";
import { isMacOS, isWindows } from "@/lib/platform";
import trayScreenshotDarwin from "@/assets/img/tray-darwin.png";
import trayScreenshotWindows from "@/assets/img/tray-windows.png";
import trayScreenshotLinux from "@/assets/img/tray-linux.png";

// Call at render time, not module scope: initPlatform() must run before isMacOS/isWindows.
function trayScreenshotForOS(): string {
    if (isMacOS()) return trayScreenshotDarwin;
    if (isWindows()) return trayScreenshotWindows;
    return trayScreenshotLinux;
}

type WelcomeStepTrayProps = {
    onContinue: () => void;
};

export function WelcomeStepTray({ onContinue }: Readonly<WelcomeStepTrayProps>) {
    const { t } = useTranslation();
    const trayScreenshot = trayScreenshotForOS();

    return (
        <>
            <div className={"px-1"}>
                <img
                    src={trayScreenshot}
                    alt={""}
                    className={"pointer-events-none h-auto w-full select-none rounded-2xl"}
                    draggable={false}
                />
            </div>

            <div className={"flex w-full flex-col gap-1"}>
                <DialogHeading id={"nb-welcome-title"} align={"left"}>
                    {t("welcome.title")}
                </DialogHeading>
                <DialogDescription align={"left"}>{t("welcome.description")}</DialogDescription>
            </div>

            <DialogActions>
                <Button
                    autoFocus
                    variant={"primary"}
                    size={"md"}
                    tabIndex={0}
                    className={"w-full"}
                    onClick={onContinue}
                >
                    {t("welcome.continue")}
                </Button>
            </DialogActions>
        </>
    );
}
