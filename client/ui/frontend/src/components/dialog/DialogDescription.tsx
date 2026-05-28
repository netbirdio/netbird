import { ReactNode } from "react";
import { cn } from "@/lib/cn";

// DialogDescription is the supporting description text rendered under a
// DialogHeading inside ConfirmDialog (and similar dialog surfaces).
type DialogDescriptionProps = {
    children: ReactNode;
    className?: string;
};

export const DialogDescription = ({ children, className }: DialogDescriptionProps) => (
    <p className={cn("text-sm text-nb-gray-300 select-none", className)}>{children}</p>
);
