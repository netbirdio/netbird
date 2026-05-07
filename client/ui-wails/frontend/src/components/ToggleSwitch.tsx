"use client";

import * as SwitchPrimitives from "@radix-ui/react-switch";
import { cva, VariantProps } from "class-variance-authority";
import * as React from "react";
import { cn } from "@/lib/cn";

type SwitchVariants = VariantProps<typeof switchVariants>;

const switchVariants = cva("", {
  variants: {
    size: {
      default: "h-[24px] w-[44px]",
      small: "h-[18px] w-[36px]",
    },
    variant: {
      default: [
        "dark:data-[state=checked]:bg-netbird dark:data-[state=unchecked]:bg-nb-gray-700",
        "data-[state=checked]:bg-neutral-900 data-[state=unchecked]:bg-neutral-200",
      ],
      "red-green": [
        "dark:data-[state=checked]:bg-red-600 dark:data-[state=unchecked]:bg-nb-gray-700",
        "data-[state=checked]:bg-red-500 data-[state=unchecked]:bg-red-200",
      ],
      red: [
        "dark:data-[state=checked]:bg-red-600 dark:data-[state=unchecked]:bg-nb-gray-700",
        "data-[state=checked]:bg-red-500 data-[state=unchecked]:bg-red-200",
      ],
    },
    "thumb-size": {
      default: "h-5 w-5 data-[state=checked]:translate-x-5",
      small: "h-[14px] w-[14px] data-[state=checked]:translate-x-[17px]",
    },
  },
});

const ToggleSwitch = React.forwardRef<
  React.ElementRef<typeof SwitchPrimitives.Root>,
  React.ComponentPropsWithoutRef<typeof SwitchPrimitives.Root> &
    SwitchVariants & { dataCy?: string }
>(
  (
    { className, size = "default", variant = "default", dataCy, ...props },
    ref,
  ) => (
    <SwitchPrimitives.Root
      className={cn(
        "peer inline-flex shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-950 focus-visible:ring-offset-2 focus-visible:ring-offset-white disabled:cursor-not-allowed disabled:opacity-50 dark:focus-visible:ring-neutral-300 dark:focus-visible:ring-offset-neutral-950",
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
          "pointer-events-none block rounded-full bg-white shadow-lg ring-0 transition-transform data-[state=unchecked]:translate-x-0 dark:bg-white",
        )}
      />
    </SwitchPrimitives.Root>
  ),
);
ToggleSwitch.displayName = SwitchPrimitives.Root.displayName;

export { ToggleSwitch };
