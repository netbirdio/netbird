import { type ButtonHTMLAttributes, type ComponentType, forwardRef } from "react";
import { type LucideProps } from "lucide-react";
import { useFocusVisible } from "@/hooks/useFocusVisible";
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
    const isFocusVisible = useFocusVisible();
    return (
        <button
            ref={ref}
            type={type}
            disabled={disabled}
            tabIndex={disabled ? -1 : 0}
            className={cn(
                "flex h-10 w-10 cursor-default items-center justify-center rounded-lg outline-none",
                "text-nb-gray-400 hover:bg-nb-gray-900 hover:text-nb-gray-300",
                isFocusVisible &&
                    "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                "wails-no-draggable transition-colors duration-150",
                className,
            )}
            {...props}
        >
            <Icon size={iconSize} className={iconClassName} />
        </button>
    );
});
