import * as RadioGroup from "@radix-ui/react-radio-group";
import { motion } from "framer-motion";
import { type ReactNode } from "react";
import { cn } from "@/lib/cn";
import { useSwitchItemGroup } from "@/components/switches/SwitchItemGroup";

type Props = {
    value: string;
    children: ReactNode;
    className?: string;
};

export const SwitchItem = ({ value, children, className }: Props) => {
    const { value: activeValue, layoutId } = useSwitchItemGroup();
    const active = activeValue === value;

    return (
        <RadioGroup.Item
            value={value}
            className={cn(
                "relative inline-flex items-center justify-center gap-1 rounded-md px-3.5 py-2 text-xs font-semibold",
                "cursor-default outline-none",
                "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                active
                    ? "text-nb-gray-100"
                    : "text-nb-gray-400 hover:text-nb-gray-200 active:text-nb-gray-100",
                className,
            )}
        >
            {active && (
                <motion.span
                    layoutId={layoutId}
                    className={"absolute inset-0 rounded-md bg-nb-gray-700"}
                    transition={{ type: "spring", stiffness: 500, damping: 35 }}
                />
            )}
            <span className={"relative inline-flex items-center justify-center gap-1"}>
                {children}
            </span>
        </RadioGroup.Item>
    );
};
