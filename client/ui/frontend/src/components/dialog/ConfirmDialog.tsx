import { ReactNode, forwardRef } from "react";
import { cn } from "@/lib/cn.ts";
import { isMacOS } from "@/lib/platform.ts";

// ConfirmDialog is the shared layout wrapper used by dialog-style window
// surfaces (SessionExpired, SessionAboutToExpire, …). Purely a layout
// primitive — callers compose the contents (SquareIcon, DialogHeading,
// DialogDescription, DialogActions) so each dialog can tweak its own
// internal structure without growing the ConfirmDialog API.
//
// Callers that mount the dialog inside its own Wails window pair this
// with useAutoSizeWindow by forwarding the returned ref onto the content
// wrapper so the window height tracks the rendered content.
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
                    "flex flex-col items-center gap-5 text-center px-8 py-6",
                    isMacOS() && "pt-10",
                )}
            >
                {children}
            </div>
        </div>
    );
});
