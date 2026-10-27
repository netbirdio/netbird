import { type ReactNode } from "react";
import { AlertTriangleIcon, CircleAlertIcon } from "lucide-react";
import { cn } from "@/lib/cn";

export type NoticeVariant = "warning" | "danger";

type Props = {
    variant?: NoticeVariant;
    className?: string;
    children: ReactNode;
};

const VARIANT_CLASSES: Record<NoticeVariant, string> = {
    warning: "border-yellow-500/30 bg-yellow-500/10 text-yellow-800 dark:text-yellow-200",
    danger: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300",
};

const VARIANT_ICONS = {
    warning: AlertTriangleIcon,
    danger: CircleAlertIcon,
} as const;

export const Notice = ({ variant = "warning", className, children }: Props) => {
    const Icon = VARIANT_ICONS[variant];
    return (
        <div
            role={"status"}
            className={cn(
                "flex items-start gap-2 rounded-md border px-3 py-2 text-xs",
                VARIANT_CLASSES[variant],
                className,
            )}
        >
            <Icon size={14} aria-hidden={"true"} className={"mt-px shrink-0"} />
            <span className={"min-w-0 flex-1"}>{children}</span>
        </div>
    );
};

export default Notice;
