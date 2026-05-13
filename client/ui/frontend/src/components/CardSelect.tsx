import * as RadioGroup from "@radix-ui/react-radio-group";
import { CheckIcon } from "lucide-react";
import { ReactNode } from "react";
import { cn } from "@/lib/cn";

type RootProps = {
    value: string;
    onChange: (value: string) => void;
    children: ReactNode;
    className?: string;
};

const Root = ({ value, onChange, children, className }: RootProps) => {
    return (
        <RadioGroup.Root
            value={value}
            onValueChange={onChange}
            className={cn("grid grid-cols-2 gap-3", className)}
        >
            {children}
        </RadioGroup.Root>
    );
};

type OptionProps = {
    value: string;
    title: string;
    description?: string;
    preview?: ReactNode;
    className?: string;
};

const Option = ({ value, title, description, preview, className }: OptionProps) => {
    return (
        <RadioGroup.Item
            value={value}
            className={cn(
                "group relative flex flex-col items-stretch text-left rounded-lg",
                "border border-nb-gray-850 bg-nb-gray-925 p-3 cursor-default outline-none",
                "transition-colors duration-150",
                "hover:border-nb-gray-800",
                "data-[state=checked]:border-netbird data-[state=checked]:ring-1 data-[state=checked]:ring-netbird",
                className,
            )}
        >
            <span
                className={cn(
                    "absolute top-2.5 right-2.5 flex h-4 w-4 items-center justify-center rounded-[4px]",
                    "border border-nb-gray-700 bg-nb-gray-900",
                    "group-data-[state=checked]:border-netbird group-data-[state=checked]:bg-netbird",
                )}
            >
                <RadioGroup.Indicator className={"flex items-center justify-center"}>
                    <CheckIcon size={11} className={"text-white"} strokeWidth={3} />
                </RadioGroup.Indicator>
            </span>
            <div
                className={cn(
                    "h-48 -mx-3 -mt-3 mb-3 overflow-hidden",
                    "bg-gradient-to-b from-nb-gray-800/15 to-nb-gray",
                    "rounded-t-lg flex items-center justify-center",
                )}
            >
                {preview}
            </div>
            <h3 className={"text-sm font-semibold text-nb-gray-100"}>{title}</h3>
            {description && (
                <p className={"text-[0.72rem] leading-snug text-nb-gray-400 mt-0.5"}>
                    {description}
                </p>
            )}
        </RadioGroup.Item>
    );
};

export const CardSelect = Object.assign(Root, { Option });
