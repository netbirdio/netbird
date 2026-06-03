import { ReactNode } from "react";
import { cn } from "@/lib/cn";

// DialogHeading is the title text used inside ConfirmDialog (and any other
// dialog-style surface with the same shape). Pair with DialogDescription
// for the standard title/description stack.
type DialogAlign = "left" | "center" | "right";

const alignClass: Record<DialogAlign, string> = {
    left: "text-left",
    center: "text-center",
    right: "text-right",
};

type DialogHeadingProps = {
    children: ReactNode;
    className?: string;
    align?: DialogAlign;
};

export const DialogHeading = ({ children, className, align = "center" }: DialogHeadingProps) => (
    // w-full so the alignClass actually has a box to anchor against.
    // The wrapping <p> defaulted to content width inside a flex column,
    // which made `text-left` a no-op (nothing to push the text away
    // from). Stretching the element is invisible for the default
    // text-center case (center of content == center of box) and lets
    // text-left/right line up with the dialog's content edge.
    <p
        className={cn(
            "w-full text-base font-semibold text-nb-gray-50 select-none",
            alignClass[align],
            className,
        )}
    >
        {children}
    </p>
);
