import { useCallback, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { AlertCircleIcon } from "lucide-react";
import { Button } from "@/components/buttons/Button";
import { ConfirmDialog } from "@/components/dialog/ConfirmDialog";
import { DialogActions } from "@/components/dialog/DialogActions";
import { DialogDescription } from "@/components/dialog/DialogDescription";
import { DialogHeading } from "@/components/dialog/DialogHeading";
import { SquareIcon } from "@/components/SquareIcon";
import { WindowManager } from "@bindings/services";
import { useAutoSizeWindow } from "@/hooks/useAutoSizeWindow";

const WINDOW_WIDTH = 380;

// ErrorDialog is the app's error surface — a frameless, always-on-top
// NetBird-chromed window opened by WindowManager.OpenError(title, message),
// which the lib/dialogs.ts errorDialog() wrapper drives in place of the old
// native OS MessageBox. Title and message arrive as query params (see
// services/windowmanager.go errorDialogURL); both are caller-localised. The
// title is also the window's chrome title ("NetBird - <title>", set Go-side);
// it's repeated as the heading here so it stays visible on macOS, where the
// hidden-inset title bar doesn't render the chrome title. The single Close
// button (and the Escape key) dismisses the window via WindowManager.CloseError
// — the Go side destroys it on close.
export default function ErrorDialog() {
    const { t } = useTranslation();
    const contentRef = useAutoSizeWindow<HTMLDivElement>(WINDOW_WIDTH);
    const [params] = useSearchParams();

    const title = params.get("title") || t("window.title.error");
    const message = params.get("message") || "";

    const close = useCallback(() => {
        WindowManager.CloseError().catch(console.error);
    }, []);

    // Escape closes — keyboard-accessible cancellation, matching the native
    // dialog's behaviour. The primary button is autoFocused below so Enter
    // also dismisses.
    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") close();
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [close]);

    return (
        <ConfirmDialog ref={contentRef}>
            <SquareIcon icon={AlertCircleIcon} variant={"danger"} />

            <div className={"flex flex-col items-center gap-1"}>
                <DialogHeading className={"text-balance"}>{title}</DialogHeading>
                {message && (
                    <DialogDescription className={"text-balance"}>
                        <span className={"whitespace-pre-wrap break-words"}>{message}</span>
                    </DialogDescription>
                )}
            </div>

            <DialogActions>
                <Button
                    autoFocus
                    variant={"primary"}
                    size={"md"}
                    className={"w-full"}
                    onClick={close}
                >
                    {t("common.close")}
                </Button>
            </DialogActions>
        </ConfirmDialog>
    );
}
