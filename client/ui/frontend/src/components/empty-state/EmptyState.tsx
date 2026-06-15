import { ComponentType } from "react";
import { LucideProps } from "lucide-react";
import { cn } from "@/lib/cn";
import { SquareIcon } from "@/components/SquareIcon";
import { isMacOS } from "@/lib/platform";

// Knob to shift the centered main-window content up/down together.
export const contentVerticalOffset = (): string => (isMacOS() ? "0rem" : "-1.4rem");
export const contentTop = (base: string) => `calc(${base} + ${contentVerticalOffset()})`;

type Props = {
    icon: ComponentType<LucideProps>;
    title: string;
    description?: string;
    className?: string;
};

export const EmptyState = ({ icon, title, description, className }: Props) => {
    return (
        <div className={cn("py-12 text-center", className)}>
            <div
                className={"flex flex-col items-center justify-start max-w-sm mx-auto relative"}
                style={{ top: contentTop("7.8rem") }}
            >
                <SquareIcon icon={icon} className={"mb-3"} />
                <p className={"text-[0.95rem] font-medium text-nb-gray-200 mb-1"}>{title}</p>
                {description && <p className={"text-sm text-nb-gray-350"}>{description}</p>}
            </div>
        </div>
    );
};
