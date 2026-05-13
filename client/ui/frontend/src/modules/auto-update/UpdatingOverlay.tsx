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

function classifyError(msg: string, version: string | null): Variant {
    const lower = msg.toLowerCase();
    const target = version ? `v${version}` : "the new version";
    if (lower.includes("timeout") || lower.includes("timed out")) {
        return {
            title: "Update Is Taking Too Long",
            description: `Installing ${target} took too long and didn't finish.`,
        };
    }
    if (lower.includes("cancel")) {
        return {
            title: "Update Was Stopped",
            description: `The update to ${target} was canceled before it finished.`,
        };
    }
    return {
        title: "Couldn't Install the Update",
        description: `${target} couldn't be installed.`,
        message: msg || "unknown error",
    };
}

export const UpdatingOverlay = ({ version, error, onDismiss }: Props) => {
    const isError = Boolean(error);
    const errorInfo = error ? classifyError(error, version) : null;

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
                                ? `Updating NetBird to v${version}`
                                : "Updating NetBird"}
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
                            "A newer version is available and is being installed. NetBird will restart automatically once the update is finished."
                        )}
                    </p>
                </div>

                {isError && (
                    <div className={"wails-no-draggable"}>
                        <Button variant={"secondary"} size={"xs"} onClick={onDismiss}>
                            Close
                        </Button>
                    </div>
                )}
            </div>
        </div>
    );
};
