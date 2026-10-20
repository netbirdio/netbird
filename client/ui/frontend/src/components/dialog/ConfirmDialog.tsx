import { type ReactNode, forwardRef } from "react";
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
                "wails-draggable static m-0 flex max-h-none w-full max-w-none select-none flex-col items-center border-0 bg-transparent p-0 text-inherit"
            }
        >
            <div
                ref={ref}
                className={cn(
                    "flex flex-col items-center gap-5 px-8 pb-7 pt-6 text-center",
                    isMacOS() && "pt-10",
                )}
            >
                {children}
            </div>
        </dialog>
    );
});
