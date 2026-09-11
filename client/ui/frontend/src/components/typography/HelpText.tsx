import { type ReactNode } from "react";
import { cn } from "@/lib/cn";

type Props = {
    children?: ReactNode;
    margin?: boolean;
    className?: string;
    disabled?: boolean;
};

export const HelpText = ({ children, margin = true, className, disabled = false }: Props) => (
    <span
        className={cn(
            "block text-[.81rem] font-light tracking-wide transition-all duration-300 dark:text-nb-gray-300",
            margin && "mb-2",
            disabled && "pointer-events-none opacity-30",
            className,
        )}
    >
        {children}
    </span>
);

export default HelpText;
