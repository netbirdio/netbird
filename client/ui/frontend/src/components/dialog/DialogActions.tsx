import { ReactNode } from "react";
import { cn } from "@/lib/cn";

type DialogActionsProps = {
    children: ReactNode;
    className?: string;
};

export const DialogActions = ({ children, className }: DialogActionsProps) => (
    <div className={cn("wails-no-draggable flex flex-col gap-3 w-full mx-auto", className)}>
        {children}
    </div>
);
