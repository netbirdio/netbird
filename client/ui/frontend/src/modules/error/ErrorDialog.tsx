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

export default function ErrorDialog() {
    const { t } = useTranslation();
    const contentRef = useAutoSizeWindow<HTMLDivElement>(WINDOW_WIDTH);
    const [params] = useSearchParams();

    const title = params.get("title") || t("window.title.error");
    const message = params.get("message") || "";

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

            <div className={"flex flex-col items-center gap-1"}>
                <DialogHeading id={"nb-error-dialog-title"} className={"text-balance"}>
                    {title}
                </DialogHeading>
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
