import { ReactNode } from "react";
import { cn } from "@/lib/cn";

// DialogDescription is the supporting description text rendered under a
// DialogHeading inside ConfirmDialog (and similar dialog surfaces).
type DialogAlign = "left" | "center" | "right";

const alignClass: Record<DialogAlign, string> = {
    left: "text-left",
    center: "text-center",
    right: "text-right",
};

type DialogDescriptionProps = {
    children: ReactNode;
    className?: string;
    align?: DialogAlign;
};

export const DialogDescription = ({ children, className, align = "center" }: DialogDescriptionProps) => (
    // w-full for the same reason DialogHeading carries it — see the
    // comment there. The default text-center remains visually identical
    // to before; left/right alignment now anchors to the dialog content
    // edge instead of collapsing to no-op on a content-width box.
    <p
        className={cn(
            "w-full text-sm text-nb-gray-300 select-none",
            alignClass[align],
            className,
        )}
    >
        {children}
    </p>
);
