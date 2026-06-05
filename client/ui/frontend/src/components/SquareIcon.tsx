import { ComponentType } from "react";
import { LucideProps } from "lucide-react";
import { cn } from "@/lib/cn";

// SquareIcon is the rounded-square icon tile used by dialog-style surfaces
// (ConfirmDialog, etc.). Renders a bordered tile with the provided lucide
// icon centered inside. The `tone` selects the semantic colour scheme —
// `default` keeps the neutral dark tile; info/warning/danger tint the tile,
// border and icon to match the action's severity.
export type SquareIconTone = "default" | "info" | "warning" | "danger";

const toneClass: Record<SquareIconTone, string> = {
    default: "bg-nb-gray-920 border-nb-gray-900 text-white",
    info: "bg-sky-950 border-sky-500 text-sky-100",
    warning: "bg-netbird-950 border-netbird text-netbird",
    danger: "bg-red-950 border-red-500 text-red-500",
};

type SquareIconProps = {
    icon: ComponentType<LucideProps>;
    iconSize?: number;
    tone?: SquareIconTone;
    className?: string;
};

export const SquareIcon = ({
    icon: Icon,
    iconSize = 20,
    tone = "default",
    className,
}: SquareIconProps) => (
    <div
        className={cn(
            "h-11 w-11 rounded-lg flex items-center justify-center border",
            toneClass[tone],
            className,
        )}
    >
        <Icon size={iconSize} />
    </div>
);
