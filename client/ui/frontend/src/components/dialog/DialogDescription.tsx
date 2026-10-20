import { type ReactNode } from "react";
import { cn } from "@/lib/cn";

type DialogAlign = "start" | "center" | "end";

const alignClass: Record<DialogAlign, string> = {
    start: "text-start",
    center: "text-center",
    end: "text-end",
};

type DialogDescriptionProps = {
    children: ReactNode;
    className?: string;
    align?: DialogAlign;
};

export const DialogDescription = ({
    children,
    className,
    align = "center",
}: DialogDescriptionProps) => (
    <p className={cn("w-full select-none text-sm text-nb-gray-300", alignClass[align], className)}>
        {children}
    </p>
);
