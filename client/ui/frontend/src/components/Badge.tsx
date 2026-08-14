import { forwardRef, type ComponentType, type HTMLAttributes } from "react";
import type { LucideProps } from "lucide-react";
import { cn } from "@/lib/cn";

export type BadgeVariant = "info" | "neutral" | "brand" | "success" | "warning" | "danger";

type Props = HTMLAttributes<HTMLSpanElement> & {
    variant?: BadgeVariant;
    icon?: ComponentType<LucideProps>;
    iconSize?: number;
};

const VARIANT_CLASSES: Record<BadgeVariant, string> = {
    info: "bg-sky-900 border border-sky-700 text-sky-200",
    neutral: "bg-nb-gray-900 border border-nb-gray-850 text-nb-gray-200",
    brand: "bg-netbird/15 border border-netbird/30 text-netbird",
    success: "bg-green-900 border border-green-700 text-green-200",
    warning: "bg-yellow-900 border border-yellow-700 text-yellow-200",
    danger: "bg-red-900 border border-red-700 text-red-200",
};

export const Badge = forwardRef<HTMLSpanElement, Props>(function Badge(
    { variant = "info", icon: Icon, iconSize = 10, className, children, ...rest },
    ref,
) {
    return (
        <span
            ref={ref}
            className={cn(
                "relative top-px inline-flex items-center gap-1 rounded-full px-1.5 py-[0.15rem]",
                "shrink-0 text-[0.64rem] font-semibold leading-none",
                VARIANT_CLASSES[variant],
                className,
            )}
            {...rest}
        >
            {Icon && <Icon size={iconSize} aria-hidden={"true"} />}
            {children}
        </span>
    );
});

export default Badge;
