import { ReactNode } from "react";
import { cn } from "@/lib/cn";

// DialogActions wraps a vertical stack of Buttons inside a dialog surface.
// The wails-no-draggable class lets the user click the buttons even when
// the dialog window itself is draggable from any background region.
type DialogActionsProps = {
    children: ReactNode;
    className?: string;
};

export const DialogActions = ({ children, className }: DialogActionsProps) => (
    <div
        className={cn(
            "wails-no-draggable flex flex-col gap-3 w-full mx-auto",
            className,
        )}
    >
        {children}
    </div>
);
