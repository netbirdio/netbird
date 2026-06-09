import { ReactNode } from "react";
import { cn } from "@/lib/cn";

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
