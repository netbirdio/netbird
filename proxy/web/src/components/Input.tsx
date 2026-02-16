import { cn } from "@/utils/helpers";
import { Eye, EyeOff } from "lucide-react";
import * as React from "react";
import { useState } from "react";

export interface InputProps
  extends React.InputHTMLAttributes<HTMLInputElement> {
  customPrefix?: React.ReactNode;
  customSuffix?: React.ReactNode;
  maxWidthClass?: string;
  icon?: React.ReactNode;
  error?: string;
  prefixClassName?: string;
  showPasswordToggle?: boolean;
  variant?: "default" | "darker";
}

const variantStyles = {
  default: [
    "bg-nb-gray-900 placeholder:text-neutral-400/70 border-nb-gray-700",
    "ring-offset-neutral-950/50 focus-visible:ring-neutral-500/20",
  ],
  darker: [
    "bg-nb-gray-920 placeholder:text-neutral-400/70 border-nb-gray-800",
    "ring-offset-neutral-950/50 focus-visible:ring-neutral-500/20",
  ],
  error: [
    "bg-nb-gray-900 placeholder:text-neutral-400/70 border-red-500 text-red-500",
    "ring-offset-red-500/10 focus-visible:ring-red-500/10",
  ],
};

const prefixSuffixStyles = {
  default: "bg-nb-gray-900 border-nb-gray-700 text-nb-gray-300",
  error: "bg-nb-gray-900 border-red-500 text-nb-gray-300 text-red-500",
};

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  (
    {
      className,
      type,
      customSuffix,
      customPrefix,
      icon,
      maxWidthClass = "",
      error,
      variant = "default",
      prefixClassName,
      showPasswordToggle = false,
      ...props
    },
    ref
  ) => {
    const [showPassword, setShowPassword] = useState(false);
    const isPasswordType = type === "password";
    const inputType = isPasswordType && showPassword ? "text" : type;

    const passwordToggle =
      isPasswordType && showPasswordToggle ? (
        <button
          type="button"
          onClick={() => setShowPassword(!showPassword)}
          className="hover:text-white transition-all"
          aria-label="Toggle password visibility"
        >
          {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
        </button>
      ) : null;

    const suffix = passwordToggle || customSuffix;
    const activeVariant = error ? "error" : variant;

    return (
      <>
        <div className={cn("flex relative h-[42px]", maxWidthClass)}>
          {customPrefix && (
            <div
              className={cn(
                prefixSuffixStyles[error ? "error" : "default"],
                "flex h-[42px] w-auto rounded-l-md px-3 py-2 text-sm",
                "border items-center whitespace-nowrap",
                props.disabled && "opacity-40",
                prefixClassName
              )}
            >
              {customPrefix}
            </div>
          )}

          <div
            className={cn(
              "absolute left-0 top-0 h-full flex items-center text-xs text-nb-gray-300 pl-3 leading-[0]",
              props.disabled && "opacity-40"
            )}
          >
            {icon}
          </div>

          <input
            type={inputType}
            ref={ref}
            {...props}
            className={cn(
              variantStyles[activeVariant],
              "flex h-[42px] w-full rounded-md px-3 py-2 text-sm",
              "file:bg-transparent file:text-sm file:font-medium file:border-0",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2",
              "disabled:cursor-not-allowed disabled:opacity-40",
              "border",
              customPrefix && "!border-l-0 !rounded-l-none",
              suffix && "!pr-16",
              icon && "!pl-10",
              className
            )}
          />

          <div
            className={cn(
              "absolute right-0 top-0 h-full flex items-center text-xs text-nb-gray-300 pr-4 leading-[0] select-none",
              props.disabled && "opacity-30"
            )}
          >
            {suffix}
          </div>
        </div>
        {error && (
          <p className="text-xs text-red-500 mt-2">{error}</p>
        )}
      </>
    );
  }
);

Input.displayName = "Input";

export { Input };
