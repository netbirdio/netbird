import { ComponentType, forwardRef } from "react";
import { motion, HTMLMotionProps } from "framer-motion";
import { LucideProps } from "lucide-react";
import { cn } from "@/lib/cn";

type Props = HTMLMotionProps<"button"> & {
    icon: ComponentType<LucideProps>;
    iconSize?: number;
    iconClassName?: string;
};

export const IconButton = forwardRef<HTMLButtonElement, Props>(function IconButton(
    { icon: Icon, iconSize = 17, iconClassName, className, type = "button", ...props },
    ref,
) {
    return (
        <motion.button
            ref={ref}
            type={type}
            whileTap={{ scale: 0.95 }}
            className={cn(
                "h-10 w-10 flex items-center justify-center rounded-lg cursor-default outline-none",
                "text-nb-gray-400 hover:text-nb-gray-300 hover:bg-nb-gray-900",
                "transition-colors duration-150",
                className,
            )}
            {...props}
        >
            <Icon size={iconSize} className={iconClassName} />
        </motion.button>
    );
});
