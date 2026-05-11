import { InputHTMLAttributes, forwardRef } from "react";
import { cn } from "../lib/cn";

interface Props extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
}

export const Input = forwardRef<HTMLInputElement, Props>(function Input(
  { label, className, id, ...rest },
  ref,
) {
  const inputId = id ?? label?.toLowerCase().replace(/\s+/g, "-");
  return (
    <div className="flex flex-col gap-1">
      {label && (
        <label htmlFor={inputId} className="text-xs font-medium text-nb-gray-600 dark:text-nb-gray-300">
          {label}
        </label>
      )}
      <input
        id={inputId}
        ref={ref}
        className={cn(
          "h-9 rounded-md border border-nb-gray-300 bg-white px-3 text-sm",
          "focus:border-netbird focus:outline-none focus:ring-1 focus:ring-netbird",
          "dark:border-nb-gray-700 dark:bg-nb-gray-925 dark:text-nb-gray-50",
          className,
        )}
        {...rest}
      />
    </div>
  );
});
