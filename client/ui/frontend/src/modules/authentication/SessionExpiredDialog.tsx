import { useCallback } from "react";
import { useTranslation } from "react-i18next";
import { Events } from "@wailsio/runtime";
import { AlertCircleIcon } from "lucide-react";
import { Button } from "@/components/Button";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DialogActions } from "@/components/DialogActions";
import { DialogDescription } from "@/components/DialogDescription";
import { DialogHeading } from "@/components/DialogHeading";
import { SquareIcon } from "@/components/SquareIcon";
import { WindowManager } from "@bindings/services";
import { useAutoSizeWindow } from "@/lib/useAutoSizeWindow";

const EVENT_TRIGGER_LOGIN = "trigger-login";
const WINDOW_WIDTH = 360;

export default function SessionExpiredDialog() {
    const { t } = useTranslation();
    const contentRef = useAutoSizeWindow<HTMLDivElement>(WINDOW_WIDTH);

    const signIn = useCallback(() => {
        void Events.Emit(EVENT_TRIGGER_LOGIN);
        WindowManager.CloseSessionExpired().catch(console.error);
    }, []);

    const later = useCallback(() => {
        WindowManager.CloseSessionExpired().catch(console.error);
    }, []);

    return (
        <ConfirmDialog ref={contentRef}>
            <SquareIcon icon={AlertCircleIcon} className={"mt-4"} />

            <div className={"flex flex-col items-center gap-1"}>
                <DialogHeading>{t("sessionExpired.title")}</DialogHeading>
                <DialogDescription>{t("sessionExpired.description")}</DialogDescription>
            </div>

            <DialogActions>
                <Button
                    autoFocus
                    variant={"primary"}
                    size={"md"}
                    className={"w-full"}
                    onClick={signIn}
                >
                    {t("sessionExpired.signIn")}
                </Button>
                <Button variant={"secondary"} size={"md"} className={"w-full"} onClick={later}>
                    {t("sessionExpired.later")}
                </Button>
            </DialogActions>
        </ConfirmDialog>
    );
}
