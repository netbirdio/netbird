import type { ReactNode } from "react";

export const SectionGroup = ({
    title,
    children,
}: {
    title: string;
    children: ReactNode;
}) => (
    <section className={"mb-8"}>
        <h2
            className={
                "text-xs uppercase tracking-wider text-nb-gray-400 mb-3 font-semibold"
            }
        >
            {title}
        </h2>
        <div className={"flex flex-col gap-4"}>{children}</div>
    </section>
);
