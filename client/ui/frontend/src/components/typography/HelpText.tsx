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
            "text-[.81rem] dark:text-nb-gray-300 block font-light tracking-wide transition-all duration-300",
            margin && "mb-2",
            disabled && "opacity-30 pointer-events-none",
            className,
        )}
    >
        {children}
    </span>
);

export default HelpText;
