import { type ComponentType } from "react";
import { type LucideProps } from "lucide-react";
import { cn } from "@/lib/cn";

export type SquareIconVariant = "default" | "info" | "warning" | "danger";

const variantClass: Record<SquareIconVariant, string> = {
    default: "text-white",
    info: "text-sky-400",
    warning: "text-netbird",
    danger: "text-red-500",
};

type SquareIconProps = {
    icon: ComponentType<LucideProps>;
    iconSize?: number;
    variant?: SquareIconVariant;
    className?: string;
};

export const SquareIcon = ({
    icon: Icon,
    iconSize = 18,
    variant = "default",
    className,
}: SquareIconProps) => (
    <div
        aria-hidden={"true"}
        className={cn(
            "flex h-11 w-11 items-center justify-center rounded-lg border border-nb-gray-900 bg-nb-gray-920",
            variantClass[variant],
            className,
        )}
    >
        <Icon size={iconSize} />
    </div>
);
