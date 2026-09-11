import { useCallback, useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import { Loader2 } from "lucide-react";
import { Connection } from "@bindings/services";
import { Button } from "@/components/buttons/Button";
import { ConfirmDialog } from "@/components/dialog/ConfirmDialog";
import { DialogActions } from "@/components/dialog/DialogActions";
import { DialogDescription } from "@/components/dialog/DialogDescription";
import { DialogHeading } from "@/components/dialog/DialogHeading";
import { SquareIcon } from "@/components/SquareIcon";
import { useAutoSizeWindow } from "@/hooks/useAutoSizeWindow";
import { errorDialog, formatErrorMessage } from "@/lib/errors";

const EVENT_CANCEL = "browser-login:cancel";
const WINDOW_WIDTH = 360;

export default function LoginWaitingForBrowserDialog() {
    const { t } = useTranslation();
    const [params] = useSearchParams();
    const uri = params.get("uri") ?? "";
    const contentRef = useAutoSizeWindow<HTMLDivElement>(WINDOW_WIDTH);
    const openedRef = useRef(false);

    const reportOpenFailure = useCallback(
        (e: unknown) => {
            void errorDialog({
                Title: t("browserLogin.openFailedTitle"),
                Message: formatErrorMessage(e),
            });
        },
        [t],
    );

    // Open the browser only after mount, or it lands on top of the still-hidden popup.
    useEffect(() => {
        if (!uri || openedRef.current) return;
        openedRef.current = true;
        Connection.OpenURL(uri).catch(reportOpenFailure);
    }, [uri, reportOpenFailure]);

    const tryAgain = useCallback(() => {
        if (!uri) return;
        Connection.OpenURL(uri).catch(reportOpenFailure);
    }, [uri, reportOpenFailure]);

    const cancel = useCallback(() => {
        Events.Emit(EVENT_CANCEL).catch((err: unknown) =>
            console.error("emit browser-login cancel", err),
        );
    }, []);

    return (
        <ConfirmDialog ref={contentRef} aria-labelledby={"nb-browser-login-title"}>
            <SquareIcon icon={Loader2} className={"[&_svg]:animate-spin"} />

            <div className={"flex flex-col items-center gap-2"}>
                <DialogHeading id={"nb-browser-login-title"} className={"text-balance"}>
                    {t("browserLogin.title")}
                </DialogHeading>
                <DialogDescription>
                    {t("browserLogin.notSeeing")}{" "}
                    <button
                        type={"button"}
                        onClick={tryAgain}
                        disabled={!uri}
                        className={
                            "wails-no-draggable text-netbird hover:underline disabled:cursor-not-allowed disabled:opacity-40"
                        }
                    >
                        {t("browserLogin.tryAgain")}
                    </button>
                </DialogDescription>
            </div>

            <DialogActions>
                <Button
                    autoFocus
                    variant={"secondary"}
                    size={"md"}
                    className={"w-full"}
                    onClick={cancel}
                >
                    {t("common.cancel")}
                </Button>
            </DialogActions>
        </ConfirmDialog>
    );
}
