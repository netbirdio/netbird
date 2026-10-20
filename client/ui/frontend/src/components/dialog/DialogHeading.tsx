import { type ReactNode } from "react";
import { cn } from "@/lib/cn";

type DialogAlign = "start" | "center" | "end";

const alignClass: Record<DialogAlign, string> = {
    start: "text-start",
    center: "text-center",
    end: "text-end",
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
