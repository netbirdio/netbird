import { useCallback, useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { Dialogs, Events } from "@wailsio/runtime";
import { Loader2 } from "lucide-react";
import { Connection } from "@bindings/services";
import { Button } from "@/components/buttons/Button";
import { ConfirmDialog } from "@/components/dialog/ConfirmDialog";
import { DialogActions } from "@/components/dialog/DialogActions";
import { DialogDescription } from "@/components/dialog/DialogDescription";
import { DialogHeading } from "@/components/dialog/DialogHeading";
import { SquareIcon } from "@/components/SquareIcon";
import { useAutoSizeWindow } from "@/hooks/useAutoSizeWindow";
import { formatErrorMessage } from "@/lib/errors";

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
            void Dialogs.Error({
                Title: t("browserLogin.openFailedTitle"),
                Message: formatErrorMessage(e),
            });
        },
        [t],
    );

    // Open the system browser only after the dialog has mounted (which
    // means useAutoSizeWindow has called Window.Show). startLogin used to
    // fire OpenURL itself but the browser typically beat React's mount
    // and landed on top of the still-hidden NetBird popup. The ref guard
    // keeps StrictMode's intentional double-invoke in dev (and any future
    // remount) from launching two browser tabs.
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
        void Events.Emit(EVENT_CANCEL);
    }, []);

    return (
        <ConfirmDialog ref={contentRef}>
            <SquareIcon
                icon={Loader2}
                className={"mt-4 [&_svg]:animate-spin"}
            />

            <div className={"flex flex-col items-center gap-2"}>
                <DialogHeading className={"text-balance"}>
                    {t("browserLogin.title")}
                </DialogHeading>
                <DialogDescription>
                    {t("browserLogin.notSeeing")}{" "}
                    <button
                        type={"button"}
                        onClick={tryAgain}
                        disabled={!uri}
                        className={
                            "wails-no-draggable text-netbird hover:underline disabled:opacity-40 disabled:cursor-not-allowed"
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
