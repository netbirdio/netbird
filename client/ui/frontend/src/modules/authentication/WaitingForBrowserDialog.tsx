import { useCallback } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import { Loader2 } from "lucide-react";
import { Connection } from "@bindings/services";
import { Button } from "@/components/Button";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DialogActions } from "@/components/DialogActions";
import { DialogDescription } from "@/components/DialogDescription";
import { DialogHeading } from "@/components/DialogHeading";
import { SquareIcon } from "@/components/SquareIcon";
import { useAutoSizeWindow } from "@/lib/useAutoSizeWindow";

const EVENT_CANCEL = "browser-login:cancel";
const WINDOW_WIDTH = 360;

export default function WaitingForBrowserDialog() {
    const { t } = useTranslation();
    const [params] = useSearchParams();
    const uri = params.get("uri") ?? "";
    const contentRef = useAutoSizeWindow<HTMLDivElement>(WINDOW_WIDTH);

    const tryAgain = useCallback(() => {
        if (!uri) return;
        Connection.OpenURL(uri).catch(console.error);
    }, [uri]);

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
