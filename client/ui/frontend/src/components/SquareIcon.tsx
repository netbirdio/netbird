import { ComponentType } from "react";
import { LucideProps } from "lucide-react";
import { cn } from "@/lib/cn";

// SquareIcon is the rounded-square icon tile used by dialog-style surfaces
// (ConfirmDialog, etc.). Renders a bordered dark tile with the provided
// lucide icon centered inside.
type SquareIconProps = {
    icon: ComponentType<LucideProps>;
    iconSize?: number;
    className?: string;
};

export const SquareIcon = ({ icon: Icon, iconSize = 20, className }: SquareIconProps) => (
    <div
        className={cn(
            "h-11 w-11 rounded-xl flex items-center justify-center bg-nb-gray-920 border border-nb-gray-900 text-white",
            className,
        )}
    >
        <Icon size={iconSize} />
    </div>
);
