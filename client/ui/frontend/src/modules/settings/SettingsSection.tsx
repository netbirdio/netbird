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

// SettingsBottomBar renders the floating action bar at the bottom of a
// settings tab (Save Changes / Add Profile / Create Bundle). It pairs the
// absolutely positioned bar with an in-flow spacer of the same height so
// scrollable content above doesn't end up hidden behind the bar.
export const SettingsBottomBar = ({ children }: { children: ReactNode }) => (
    <>
        <div className={"h-[4.5rem] shrink-0"} aria-hidden />
        <div className={"absolute bottom-0 left-0 w-full"}>
            <div
                className={
                    "w-full flex justify-end gap-3 px-8 py-5 border-t border-nb-gray-920 bg-nb-gray-940"
                }
            >
                {children}
            </div>
        </div>
    </>
);
