import { ButtonHTMLAttributes, forwardRef } from "react";
import { cn } from "../lib/cn";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const variants: Record<Variant, string> = {
  primary: "bg-netbird text-white hover:bg-netbird-500 disabled:bg-nb-gray-300",
  secondary:
    "bg-nb-gray-100 text-nb-gray-900 hover:bg-nb-gray-200 dark:bg-nb-gray-900 dark:text-nb-gray-50 dark:hover:bg-nb-gray-800",
  ghost:
    "bg-transparent text-nb-gray-700 hover:bg-nb-gray-100 dark:text-nb-gray-200 dark:hover:bg-nb-gray-900",
  danger: "bg-red-600 text-white hover:bg-red-500",
};

const sizes: Record<Size, string> = {
  sm: "h-7 px-2 text-xs",
  md: "h-9 px-3 text-sm",
};

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

export const Button = forwardRef<HTMLButtonElement, Props>(function Button(
  { variant = "primary", size = "md", className, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-md font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60",
        variants[variant],
        sizes[size],
        className,
      )}
      {...rest}
    />
  );
});
