"use client";

import * as SwitchPrimitives from "@radix-ui/react-switch";
import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";
import { cn } from "@/lib/cn";

type SwitchVariants = VariantProps<typeof switchVariants>;

const switchVariants = cva("", {
    variants: {
        size: {
            default: "h-[24px] w-[44px]",
            small: "h-[18px] w-[36px]",
            large: "h-[36px] w-[66px]",
        },
        variant: {
            default: [
                "dark:data-[state=checked]:bg-netbird dark:data-[state=unchecked]:bg-nb-gray-700",
                "dark:data-[state=checked]:hover:bg-netbird-500 dark:data-[state=unchecked]:hover:bg-nb-gray-600",
                "data-[state=checked]:bg-neutral-900 data-[state=unchecked]:bg-neutral-200",
                "data-[state=checked]:hover:bg-neutral-800 data-[state=unchecked]:hover:bg-neutral-300",
            ],
            "red-green": [
                "dark:data-[state=checked]:bg-red-600 dark:data-[state=unchecked]:bg-nb-gray-700",
                "dark:data-[state=checked]:hover:bg-red-500 dark:data-[state=unchecked]:hover:bg-nb-gray-600",
                "data-[state=checked]:bg-red-500 data-[state=unchecked]:bg-red-200",
                "data-[state=checked]:hover:bg-red-400 data-[state=unchecked]:hover:bg-red-300",
            ],
            red: [
                "dark:data-[state=checked]:bg-red-600 dark:data-[state=unchecked]:bg-nb-gray-700",
                "dark:data-[state=checked]:hover:bg-red-500 dark:data-[state=unchecked]:hover:bg-nb-gray-600",
                "data-[state=checked]:bg-red-500 data-[state=unchecked]:bg-red-200",
                "data-[state=checked]:hover:bg-red-400 data-[state=unchecked]:hover:bg-red-300",
            ],
        },
        "thumb-size": {
            default:
                "h-5 w-5 data-[state=checked]:translate-x-5 data-[state=unchecked]:translate-x-0",
            small: "h-[14px] w-[14px] data-[state=checked]:translate-x-[17px] data-[state=unchecked]:translate-x-0",
            large: "h-[30px] w-[30px] data-[state=checked]:translate-x-[31px] data-[state=unchecked]:translate-x-[1px]",
        },
    },
});

const ToggleSwitch = React.forwardRef<
    React.ElementRef<typeof SwitchPrimitives.Root>,
    React.ComponentPropsWithoutRef<typeof SwitchPrimitives.Root> &
        SwitchVariants & { dataCy?: string }
>(({ className, size = "default", variant = "default", dataCy, disabled, ...props }, ref) => (
    <SwitchPrimitives.Root
        disabled={disabled}
        tabIndex={disabled ? -1 : 0}
        className={cn(
            "wails-no-draggable peer inline-flex shrink-0 cursor-default items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940 disabled:cursor-not-allowed disabled:opacity-50",
            className,
            switchVariants({ size, variant }),
        )}
        {...props}
        data-cy={dataCy}
        onClick={(e) => {
            e.stopPropagation();
            props.onClick?.(e);
        }}
        ref={ref}
    >
        <SwitchPrimitives.Thumb
            className={cn(
                switchVariants({ "thumb-size": size }),
                "pointer-events-none block rounded-full bg-white shadow-lg ring-0 transition-transform dark:bg-white",
            )}
        />
    </SwitchPrimitives.Root>
));
ToggleSwitch.displayName = SwitchPrimitives.Root.displayName;

export { ToggleSwitch };
