import { type ReactNode } from "react";
import { cn } from "@/lib/cn";

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

export const DialogDescription = ({
    children,
    className,
    align = "center",
}: DialogDescriptionProps) => (
    <p className={cn("w-full text-sm text-nb-gray-300 select-none", alignClass[align], className)}>
        {children}
    </p>
);
