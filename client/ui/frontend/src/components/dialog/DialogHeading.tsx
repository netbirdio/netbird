import { type ReactNode } from "react";
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
    id?: string;
};

export const DialogHeading = ({
    children,
    className,
    align = "center",
    id,
}: DialogHeadingProps) => (
    <h2
        id={id}
        className={cn(
            "w-full select-none text-base font-semibold text-nb-gray-50",
            alignClass[align],
            className,
        )}
    >
        {children}
    </h2>
);
