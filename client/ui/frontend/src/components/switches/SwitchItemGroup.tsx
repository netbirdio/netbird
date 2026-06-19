import * as RadioGroup from "@radix-ui/react-radio-group";
import { createContext, type ReactNode, useContext, useId, useMemo } from "react";
import { cn } from "@/lib/cn";

type SwitchItemGroupContextValue = {
    value: string;
    layoutId: string;
};

const SwitchItemGroupContext = createContext<SwitchItemGroupContextValue | null>(null);

export const useSwitchItemGroup = () => {
    const ctx = useContext(SwitchItemGroupContext);
    if (!ctx) {
        throw new Error("SwitchItem must be used inside a SwitchItemGroup");
    }
    return ctx;
};

type Props = {
    value: string;
    onChange: (value: string) => void;
    children: ReactNode;
    className?: string;
    disabled?: boolean;
    "aria-label"?: string;
    "aria-labelledby"?: string;
};

export const SwitchItemGroup = ({
    value,
    onChange,
    children,
    className,
    disabled = false,
    "aria-label": ariaLabel,
    "aria-labelledby": ariaLabelledBy,
}: Props) => {
    const layoutId = useId();
    const contextValue = useMemo(() => ({ value, layoutId }), [value, layoutId]);

    return (
        <SwitchItemGroupContext.Provider value={contextValue}>
            <RadioGroup.Root
                value={value}
                onValueChange={onChange}
                disabled={disabled}
                aria-label={ariaLabel}
                aria-labelledby={ariaLabelledBy}
                className={cn(
                    "flex shrink-0 overflow-hidden rounded-lg border border-nb-gray-850 bg-nb-gray-910 p-1",
                    disabled && "pointer-events-none opacity-50",
                    className,
                )}
            >
                {children}
            </RadioGroup.Root>
        </SwitchItemGroupContext.Provider>
    );
};
