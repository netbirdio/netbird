import { ReactNode } from "react";
import { cn } from "@/lib/cn";

// DialogHeading is the title text used inside ConfirmDialog (and any other
// dialog-style surface with the same shape). Pair with DialogDescription
// for the standard title/description stack.
type DialogHeadingProps = {
    children: ReactNode;
    className?: string;
};

export const DialogHeading = ({ children, className }: DialogHeadingProps) => (
    <p className={cn("text-base font-semibold text-nb-gray-50", className)}>
        {children}
    </p>
);
