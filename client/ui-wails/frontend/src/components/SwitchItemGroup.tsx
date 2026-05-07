import * as RadioGroup from "@radix-ui/react-radio-group";
import { createContext, ReactNode, useContext, useId } from "react";
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
};

export const SwitchItemGroup = ({ value, onChange, children, className }: Props) => {
    const layoutId = useId();

    return (
        <SwitchItemGroupContext.Provider value={{ value, layoutId }}>
            <RadioGroup.Root
                value={value}
                onValueChange={onChange}
                className={cn(
                    "flex shrink-0 rounded-lg border border-nb-gray-850 bg-nb-gray-910 p-1",
                    className,
                )}
            >
                {children}
            </RadioGroup.Root>
        </SwitchItemGroupContext.Provider>
    );
};
