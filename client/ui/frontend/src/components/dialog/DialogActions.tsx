import { type ReactNode } from "react";
import { cn } from "@/lib/cn";

type DialogActionsProps = {
    children: ReactNode;
    className?: string;
};

export const DialogActions = ({ children, className }: DialogActionsProps) => (
    <div className={cn("wails-no-draggable mx-auto flex w-full flex-col gap-3", className)}>
        {children}
    </div>
);
