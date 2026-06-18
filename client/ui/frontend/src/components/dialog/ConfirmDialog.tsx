import { ReactNode, forwardRef } from "react";
import { cn } from "@/lib/cn.ts";
import { isMacOS } from "@/lib/platform.ts";

type ConfirmDialogProps = {
    children: ReactNode;
    "aria-label"?: string;
    "aria-labelledby"?: string;
};

export const ConfirmDialog = forwardRef<HTMLDivElement, ConfirmDialogProps>(function ConfirmDialog(
    { children, "aria-label": ariaLabel, "aria-labelledby": ariaLabelledBy },
    ref,
) {
    return (
        <dialog
            open
            aria-label={ariaLabel}
            aria-labelledby={ariaLabelledBy}
            className={
                "wails-draggable select-none flex flex-col items-center static bg-transparent text-inherit p-0 m-0 max-w-none max-h-none border-0 w-full"
            }
        >
            <div
                ref={ref}
                className={cn(
                    "flex flex-col items-center gap-5 text-center px-8 pt-6 pb-7",
                    isMacOS() && "pt-10",
                )}
            >
                {children}
            </div>
        </dialog>
    );
});
