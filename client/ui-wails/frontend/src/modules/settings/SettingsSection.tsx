import type { ReactNode } from "react";

export const SectionGroup = ({ title, children }: { title: string; children: ReactNode }) => (
    <section className={"mb-8 px-1"}>
        <h2 className={"text-xs uppercase tracking-wider text-nb-gray-400 mb-4 font-semibold"}>
            {title}
        </h2>
        <div className={"flex flex-col gap-5"}>{children}</div>
    </section>
);
