import * as LabelPrimitive from "@radix-ui/react-label";
import { cva, type VariantProps } from "class-variance-authority";
import { type ComponentPropsWithoutRef, forwardRef, type Ref } from "react";
import { cn } from "@/lib/cn";

const labelVariants = cva(
    "mb-1.5 inline-block flex items-center gap-2 text-sm font-medium leading-none tracking-wider peer-disabled:cursor-not-allowed peer-disabled:opacity-70 dark:text-nb-gray-100",
);

type LabelProps = ComponentPropsWithoutRef<typeof LabelPrimitive.Root> &
    VariantProps<typeof labelVariants> & {
        as?: "label" | "div";
        disabled?: boolean;
    };

export const Label = forwardRef<HTMLElement, LabelProps>(function Label(
    { className, as = "label", disabled = false, children, ...props },
    ref,
) {
    const classes = cn(
        labelVariants(),
        className,
        "select-none transition-all duration-300",
        disabled && "pointer-events-none opacity-30",
    );

    if (as === "div") {
        return (
            <div ref={ref as Ref<HTMLDivElement>} className={classes}>
                {children}
            </div>
        );
    }

    return (
        <LabelPrimitive.Root ref={ref as Ref<HTMLLabelElement>} className={classes} {...props}>
            {children}
        </LabelPrimitive.Root>
    );
});

export default Label;
