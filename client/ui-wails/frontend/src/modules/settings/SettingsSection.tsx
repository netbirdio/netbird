import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export const SectionGroup = ({
    title,
    children,
    disabled = false,
}: {
    title: string;
    children: ReactNode;
    disabled?: boolean;
}) => (
    <section className={cn("mb-8 last:mb-1 px-1", disabled && "opacity-30 pointer-events-none")}>
        <h2 className={"text-xs uppercase tracking-wider text-nb-gray-400 mb-4 font-semibold"}>
            {title}
        </h2>
        <div className={"flex flex-col gap-5"}>{children}</div>
    </section>
);
