import { type ComponentType } from "react";
import { type LucideProps } from "lucide-react";
import { cn } from "@/lib/cn";
import { SquareIcon } from "@/components/SquareIcon";
import { isMacOS } from "@/lib/platform";

// Knob to shift the centered main-window content up/down together.
export const contentVerticalOffset = (): string => (isMacOS() ? "0.6rem" : "-1.4rem");
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
                className={"relative mx-auto flex max-w-sm flex-col items-center justify-start"}
                style={{ top: contentTop("7.8rem") }}
            >
                <SquareIcon icon={icon} className={"mb-3"} />
                <p className={"mb-1 text-[0.95rem] font-medium text-nb-gray-200"}>{title}</p>
                {description && <p className={"text-sm text-nb-gray-350"}>{description}</p>}
            </div>
        </div>
    );
};
