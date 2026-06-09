import * as LabelPrimitive from "@radix-ui/react-label";
import { cva, type VariantProps } from "class-variance-authority";
import { ComponentPropsWithoutRef, forwardRef, Ref } from "react";
import { cn } from "@/lib/cn";

const labelVariants = cva(
    "text-sm font-medium tracking-wider leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 mb-1.5 inline-block dark:text-nb-gray-100 flex items-center gap-2",
);

type LabelProps = ComponentPropsWithoutRef<typeof LabelPrimitive.Root> &
    VariantProps<typeof labelVariants> & {
        as?: "label" | "div";
    };

export const Label = forwardRef<HTMLElement, LabelProps>(function Label(
    { className, as = "label", children, ...props },
    ref,
) {
    const classes = cn(labelVariants(), className, "select-none");

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
