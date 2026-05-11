import { ComponentType, forwardRef, ReactNode } from "react";
import { motion, HTMLMotionProps } from "framer-motion";
import { LucideProps } from "lucide-react";
import { cn } from "@/lib/cn";

type Props = HTMLMotionProps<"button"> & {
    icon?: ComponentType<LucideProps>;
    iconNode?: ReactNode;
    title: string;
    description?: string;
    active?: boolean;
    iconSize?: number;
};

export const CardNavItem = forwardRef<HTMLButtonElement, Props>(
    function CardNavItem(
        {
            icon: Icon,
            iconNode,
            title,
            description,
            active = false,
            iconSize = 15,
            className,
            type = "button",
            ...props
        },
        ref,
    ) {
        return (
            <motion.button
                ref={ref}
                type={type}
                whileTap={{ scale: 0.98 }}
                className={cn(
                    "w-full flex items-center gap-3 p-1.5 rounded-lg cursor-default outline-none text-left",
                    "transition-colors duration-150",
                    active ? "bg-nb-gray-930" : "hover:bg-nb-gray-940",
                    className,
                )}
                {...props}
            >
                <div
                    className={cn(
                        "h-9 w-9 rounded-md flex items-center justify-center shrink-0",
                        "transition-colors duration-150",
                        active ? "bg-nb-gray-800" : "bg-nb-gray-920",
                    )}
                >
                    {iconNode ?? (Icon && (
                        <Icon
                            size={iconSize}
                            className={cn(
                                "transition-colors duration-150",
                                active ? "text-nb-gray-200" : "text-nb-gray-400",
                            )}
                        />
                    ))}
                </div>
                <div className={"min-w-0"}>
                    <h2
                        className={cn(
                            "font-medium text-[0.81rem] truncate",
                            active ? "text-nb-gray-100" : "text-nb-gray-200",
                        )}
                    >
                        {title}
                    </h2>
                    {description && (
                        <p
                            className={cn(
                                "text-xs font-medium truncate",
                                active ? "text-nb-gray-300" : "text-nb-gray-400",
                            )}
                        >
                            {description}
                        </p>
                    )}
                </div>
            </motion.button>
        );
    },
);
