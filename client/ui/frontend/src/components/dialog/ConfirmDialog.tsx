import { ReactNode, forwardRef } from "react";
import { cn } from "@/lib/cn.ts";
import { isMacOS } from "@/lib/platform.ts";

type ConfirmDialogProps = {
    children: ReactNode;
};

export const ConfirmDialog = forwardRef<HTMLDivElement, ConfirmDialogProps>(function ConfirmDialog(
    { children },
    ref,
) {
    return (
        <div className={"wails-draggable select-none flex flex-col items-center"}>
            <div
                ref={ref}
                className={cn(
                    "flex flex-col items-center gap-5 text-center px-8 pt-6 pb-7",
                    isMacOS() && "pt-10",
                )}
            >
                {children}
            </div>
        </div>
    );
});
