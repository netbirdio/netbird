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
    <section
        aria-label={title}
        tabIndex={disabled ? -1 : 0}
        {...(disabled ? { inert: "" } : {})}
        className={cn(
            "mb-8 rounded-md px-1 outline-none last:mb-1",
            "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
            disabled && "pointer-events-none opacity-30",
        )}
    >
        <h2 className={"mb-4 text-xs font-semibold uppercase tracking-wider text-nb-gray-400"}>
            {title}
        </h2>
        <div className={"flex flex-col gap-5"}>{children}</div>
    </section>
);

export const SettingsBottomBar = ({ children }: { children: ReactNode }) => (
    <>
        <div className={"h-[3.2rem] shrink-0"} aria-hidden={"true"} />
        <div className={"absolute bottom-0 left-0 w-full"}>
            <div
                className={
                    "flex w-full justify-end gap-3 border-t border-nb-gray-920 bg-nb-gray-940 px-8 py-5"
                }
            >
                {children}
            </div>
        </div>
    </>
);
