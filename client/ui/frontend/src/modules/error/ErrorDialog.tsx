import { useCallback, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { AlertCircleIcon } from "lucide-react";
import { Button } from "@/components/buttons/Button";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { ConfirmDialog } from "@/components/dialog/ConfirmDialog";
import { DialogActions } from "@/components/dialog/DialogActions";
import { DialogDescription } from "@/components/dialog/DialogDescription";
import { DialogHeading } from "@/components/dialog/DialogHeading";
import { SquareIcon } from "@/components/SquareIcon";
import { WindowManager } from "@bindings/services";
import { useAutoSizeWindow } from "@/hooks/useAutoSizeWindow";

const WINDOW_WIDTH = 380;
// A command needs the room to wrap at a sensible number of characters instead of
// breaking every few words.
const WINDOW_WIDTH_WITH_COMMAND = 460;

export default function ErrorDialog() {
    const { t } = useTranslation();
    const [params] = useSearchParams();

    const title = params.get("title") || t("window.title.error");
    const message = params.get("message") || "";
    // Set when the daemon refused an operation that needs elevated privileges:
    // the command that performs it, offered for copying.
    const command = params.get("command") || "";
    const contentRef = useAutoSizeWindow<HTMLDivElement>(
        command ? WINDOW_WIDTH_WITH_COMMAND : WINDOW_WIDTH,
    );

    const close = useCallback(() => {
        WindowManager.CloseError().catch(console.error);
    }, []);

    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") close();
        };
        globalThis.addEventListener("keydown", onKey);
        return () => globalThis.removeEventListener("keydown", onKey);
    }, [close]);

    return (
        <ConfirmDialog ref={contentRef} aria-labelledby={"nb-error-dialog-title"}>
            <SquareIcon icon={AlertCircleIcon} variant={"danger"} />

            <div className={"flex w-full flex-col items-center gap-1"}>
                <DialogHeading id={"nb-error-dialog-title"} className={"text-balance"}>
                    {title}
                </DialogHeading>
                {message && (
                    <DialogDescription className={"text-balance"}>
                        {/* select-text: the message often names a path, a flag or an
                            address the user needs to act on. */}
                        <span className={"select-text whitespace-pre-wrap break-words"}>
                            {message}
                        </span>
                    </DialogDescription>
                )}
                {command && (
                    <CopyToClipboard
                        message={command}
                        alwaysShowIcon
                        wrap
                        variant={"bright"}
                        className={
                            "mt-2 w-full items-start gap-2 rounded-md bg-nb-gray-930 px-3 py-2 text-left"
                        }
                        aria-label={t("common.copy")}
                    >
                        <code
                            className={"select-text break-all font-mono text-xs text-nb-gray-200"}
                        >
                            {command}
                        </code>
                    </CopyToClipboard>
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
