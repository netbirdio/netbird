import { type ButtonHTMLAttributes, type ComponentType, forwardRef } from "react";
import { type LucideProps } from "lucide-react";
import { cn } from "@/lib/cn";

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
    icon: ComponentType<LucideProps>;
    iconSize?: number;
    iconClassName?: string;
};

export const IconButton = forwardRef<HTMLButtonElement, Props>(function IconButton(
    { icon: Icon, iconSize = 17, iconClassName, className, type = "button", disabled, ...props },
    ref,
) {
    return (
        <button
            ref={ref}
            type={type}
            disabled={disabled}
            tabIndex={disabled ? -1 : 0}
            className={cn(
                "h-10 w-10 flex items-center justify-center rounded-lg cursor-default outline-none",
                "text-nb-gray-400 hover:text-nb-gray-300 hover:bg-nb-gray-900",
                "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                "transition-colors duration-150 wails-no-draggable",
                className,
            )}
            {...props}
        >
            <Icon size={iconSize} className={iconClassName} />
        </button>
    );
});
