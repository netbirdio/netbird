import type { LucideIcon } from "lucide-react";
import { ChevronDown } from "lucide-react";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuRadioGroup,
    DropdownMenuRadioItem,
    DropdownMenuTrigger,
} from "@/components/DropdownMenu";
import { useFocusVisible } from "@/hooks/useFocusVisible";
import { cn } from "@/lib/cn";

export type SelectOption<T extends string> = {
    value: T;
    label: string;
    icon?: LucideIcon;
};

type SelectProps<T extends string> = {
    value: T;
    options: SelectOption<T>[];
    onChange: (value: T) => void;
    ariaLabel: string;
    disabled?: boolean;
    className?: string;
};

export function Select<T extends string>({
    value,
    options,
    onChange,
    ariaLabel,
    disabled,
    className,
}: SelectProps<T>) {
    const isFocusVisible = useFocusVisible();
    const current = options.find((o) => o.value === value) ?? options[0];
    const CurrentIcon = current?.icon;

    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <button
                    type={"button"}
                    tabIndex={0}
                    disabled={disabled}
                    aria-label={ariaLabel}
                    className={cn(
                        "inline-flex h-[40px] min-w-[160px] items-center gap-2 px-3",
                        "rounded-md border bg-white dark:bg-nb-gray-900",
                        "border-neutral-200 dark:border-nb-gray-700",
                        "cursor-default text-xs font-semibold text-nb-gray-100 outline-none",
                        "hover:border-nb-gray-700 data-[state=open]:border-nb-gray-700 dark:hover:border-nb-gray-600 dark:data-[state=open]:border-nb-gray-600",
                        isFocusVisible &&
                            "focus-visible:ring-2 focus-visible:ring-nb-gray-50/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                        "disabled:opacity-50",
                        className,
                    )}
                >
                    {CurrentIcon && (
                        <CurrentIcon
                            size={16}
                            aria-hidden={"true"}
                            className={"shrink-0 text-nb-gray-200"}
                        />
                    )}
                    <span className={"flex-1 truncate text-left"}>{current?.label ?? "—"}</span>
                    <ChevronDown
                        size={12}
                        aria-hidden={"true"}
                        className={"shrink-0 text-nb-gray-400"}
                    />
                </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
                align={"start"}
                sideOffset={6}
                className={
                    "w-[var(--radix-dropdown-menu-trigger-width)] border-nb-gray-850 bg-nb-gray-920"
                }
            >
                <DropdownMenuRadioGroup value={value} onValueChange={(v) => onChange(v as T)}>
                    {options.map(({ value: optionValue, label, icon: Icon }) => (
                        <DropdownMenuRadioItem key={optionValue} value={optionValue}>
                            {Icon && (
                                <Icon
                                    size={14}
                                    aria-hidden={"true"}
                                    className={"shrink-0 text-nb-gray-300"}
                                />
                            )}
                            <span className={"min-w-0 flex-1 truncate"}>{label}</span>
                        </DropdownMenuRadioItem>
                    ))}
                </DropdownMenuRadioGroup>
            </DropdownMenuContent>
        </DropdownMenu>
    );
}
