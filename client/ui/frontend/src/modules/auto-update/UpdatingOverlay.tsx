import { useTranslation } from "react-i18next";
import { Loader2, XCircle } from "lucide-react";
import { Button } from "@/components/Button";

type Props = {
    version: string | null;
    error: string | null;
    onDismiss: () => void;
};

type Variant = {
    title: string;
    description: string;
    message?: string;
};

function classifyError(
    msg: string,
    version: string | null,
    t: (key: string, options?: Record<string, unknown>) => string,
): Variant {
    const lower = msg.toLowerCase();
    const target = version
        ? t("update.overlay.error.targetVersion", { version })
        : t("update.overlay.error.targetFallback");
    if (lower.includes("timeout") || lower.includes("timed out")) {
        return {
            title: t("update.overlay.error.timeoutTitle"),
            description: t("update.overlay.error.timeoutDescription", { target }),
        };
    }
    if (lower.includes("cancel")) {
        return {
            title: t("update.overlay.error.canceledTitle"),
            description: t("update.overlay.error.canceledDescription", { target }),
        };
    }
    return {
        title: t("update.overlay.error.failTitle"),
        description: t("update.overlay.error.failDescription", { target }),
        message: msg || t("update.overlay.error.unknownMessage"),
    };
}

export const UpdatingOverlay = ({ version, error, onDismiss }: Props) => {
    const { t } = useTranslation();
    const isError = Boolean(error);
    const errorInfo = error ? classifyError(error, version, t) : null;

    return (
        <div
            className={
                "fixed inset-0 z-[100] flex items-center justify-center bg-nb-gray-950/85 backdrop-blur-sm cursor-default select-none wails-draggable"
            }
            onPointerDown={(e) => {
                if (isError) return;
                e.preventDefault();
                e.stopPropagation();
            }}
            onKeyDown={(e) => {
                if (isError) return;
                e.preventDefault();
                e.stopPropagation();
            }}
        >
            <div className={"flex flex-col items-center gap-5 px-8 max-w-lg text-center"}>
                {isError ? (
                    <div
                        className={"h-9 w-9 rounded-md flex items-center justify-center bg-red-500"}
                    >
                        <XCircle className={"text-white"} size={18} />
                    </div>
                ) : (
                    <div
                        className={"h-9 w-9 rounded-md flex items-center justify-center bg-nb-gray-100"}
                    >
                        <Loader2 className={"animate-spin text-nb-gray-950"} size={16} />
                    </div>
                )}

                <div className={"flex flex-col items-center gap-1"}>
                    <p className={"text-base font-medium text-nb-gray-50"}>
                        {isError
                            ? errorInfo!.title
                            : version
                                ? t("update.overlay.updatingVersion", { version })
                                : t("update.overlay.updating")}
                    </p>
                    <p className={"text-sm text-nb-gray-300"}>
                        {isError ? (
                            <>
                                {errorInfo!.description}
                                {errorInfo!.message && (
                                    <>
                                        <br />
                                        <span className={"first-letter:uppercase"}>
                                            {errorInfo!.message}
                                        </span>
                                    </>
                                )}
                            </>
                        ) : (
                            t("update.overlay.description")
                        )}
                    </p>
                </div>

                {isError && (
                    <div className={"wails-no-draggable"}>
                        <Button variant={"secondary"} size={"xs"} onClick={onDismiss}>
                            {t("common.close")}
                        </Button>
                    </div>
                )}
            </div>
        </div>
    );
};
