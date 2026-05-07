import * as RadioGroup from "@radix-ui/react-radio-group";
import { motion } from "framer-motion";
import { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { useSwitchItemGroup } from "@/components/SwitchItemGroup";

type Props = {
    value: string;
    children: ReactNode;
};

export const SwitchItem = ({ value, children }: Props) => {
    const { value: activeValue, layoutId } = useSwitchItemGroup();
    const active = activeValue === value;

    return (
        <RadioGroup.Item
            value={value}
            className={cn(
                "relative inline-flex items-center justify-center gap-1 rounded-md px-3.5 py-2 text-xs font-semibold",
                "outline-none cursor-default",
                active
                    ? "text-nb-gray-100"
                    : "text-nb-gray-400 hover:text-nb-gray-200 active:text-nb-gray-100",
            )}
        >
            {active && (
                <motion.span
                    layoutId={layoutId}
                    className={"absolute inset-0 rounded-md bg-nb-gray-800"}
                    transition={{ type: "spring", stiffness: 500, damping: 35 }}
                />
            )}
            <span
                className={"relative inline-flex items-center justify-center gap-1"}
            >
                {children}
            </span>
        </RadioGroup.Item>
    );
};
