import { ReactNode } from "react";
import { cn } from "@/lib/cn";

type Props = {
    children?: ReactNode;
    margin?: boolean;
    className?: string;
};

export const HelpText = ({ children, margin = true, className }: Props) => (
    <span
        className={cn(
            "text-[.81rem] dark:text-nb-gray-300 block font-light tracking-wide",
            margin && "mb-2",
            className,
        )}
    >
        {children}
    </span>
);

export default HelpText;
