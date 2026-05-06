import { cva, VariantProps } from "class-variance-authority";
import { AlertCircle, Eye, EyeOff } from "lucide-react";
import {
    forwardRef,
    InputHTMLAttributes,
    ReactNode,
    useId,
    useState,
} from "react";
import { cn } from "@/lib/cn";
import { Label } from "@/components/Label";

type InputVariants = VariantProps<typeof inputVariants>;

export interface InputProps
    extends InputHTMLAttributes<HTMLInputElement>,
        InputVariants {
    label?: string;
    customPrefix?: ReactNode;
    customSuffix?: ReactNode;
    maxWidthClass?: string;
    icon?: ReactNode;
    error?: string;
    prefixClassName?: string;
    showPasswordToggle?: boolean;
}

const inputVariants = cva("", {
    variants: {
        variant: {
            default: [
                "dark:bg-nb-gray-900 dark:placeholder:text-neutral-400/70 placeholder:text-neutral-500 border-neutral-200 dark:border-nb-gray-700",
                "ring-offset-neutral-200/20 dark:ring-offset-neutral-950/50 dark:focus-visible:ring-neutral-500/20 focus-visible:ring-neutral-300/10",
            ],
            darker: [
                "dark:bg-nb-gray-920 dark:placeholder:text-neutral-400/70 placeholder:text-neutral-500 border-neutral-300 dark:border-nb-gray-800",
                "ring-offset-neutral-200/20 dark:ring-offset-neutral-950/50 dark:focus-visible:ring-neutral-500/20 focus-visible:ring-neutral-300/10",
            ],
            error: [
                "dark:bg-nb-gray-900 dark:placeholder:text-neutral-400/70 placeholder:text-neutral-500 border-neutral-200 dark:border-red-500 text-red-500",
                "ring-offset-red-500/10 dark:ring-offset-red-500/10 dark:focus-visible:ring-red-500/10 focus-visible:ring-red-500/10",
            ],
        },
        prefixSuffixVariant: {
            default: [
                "dark:bg-nb-gray-900 border-neutral-200 dark:border-nb-gray-700 text-nb-gray-300",
            ],
            error: [
                "dark:bg-nb-gray-900 border-red-500 text-nb-gray-300 text-red-500",
            ],
        },
    },
});

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
    {
        className,
        type,
        label,
        customSuffix,
        customPrefix,
        icon,
        maxWidthClass = "",
        error,
        variant = "default",
        prefixClassName,
        showPasswordToggle = false,
        id,
        ...props
    },
    ref,
) {
    const [showPassword, setShowPassword] = useState(false);
    const isPasswordType = type === "password";
    const inputType = isPasswordType && showPassword ? "text" : type;

    const reactId = useId();
    const inputId =
        id ?? (label ? `input-${reactId}` : undefined);

    const passwordToggle =
        isPasswordType && showPasswordToggle ? (
            <button
                type="button"
                onClick={() => setShowPassword((s) => !s)}
                className="hover:text-white transition-all"
                aria-label="Toggle password visibility"
            >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
        ) : null;

    const suffix = passwordToggle || customSuffix;

    return (
        <div className="flex flex-col">
            {label && <Label htmlFor={inputId}>{label}</Label>}
            <div className={cn("flex relative h-[42px]", maxWidthClass)}>
                {customPrefix && (
                    <div
                        className={cn(
                            inputVariants({
                                prefixSuffixVariant: error
                                    ? "error"
                                    : "default",
                            }),
                            "flex h-[42px] w-auto rounded-l-md bg-white px-3 py-2 text-sm",
                            "border items-center whitespace-nowrap",
                            props.disabled && "opacity-40",
                            prefixClassName,
                        )}
                    >
                        {customPrefix}
                    </div>
                )}

                {icon && (
                    <div
                        className={cn(
                            "absolute left-0 top-0 h-full flex items-center text-xs dark:text-nb-gray-300 pl-3 leading-[0]",
                            props.disabled && "opacity-40",
                        )}
                    >
                        {icon}
                    </div>
                )}

                <input
                    id={inputId}
                    type={inputType}
                    ref={ref}
                    {...props}
                    className={cn(
                        inputVariants({
                            variant: error ? "error" : variant,
                        }),
                        "flex h-[42px] w-full rounded-md bg-white px-3 py-2 text-sm",
                        "file:bg-transparent file:text-sm file:font-medium file:border-0",
                        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2",
                        "disabled:cursor-not-allowed disabled:opacity-40",
                        customPrefix && "!border-l-0 !rounded-l-none",
                        suffix && "!pr-16",
                        icon && "!pl-10",
                        "border",
                        props.readOnly &&
                            "!bg-nb-gray-920 text-nb-gray-400 !border-nb-gray-800",
                        className,
                    )}
                />

                {suffix && (
                    <div
                        className={cn(
                            "absolute right-0 top-0 h-full flex items-center text-xs dark:text-nb-gray-300 pr-4 leading-[0] select-none",
                            props.disabled && "opacity-30",
                        )}
                    >
                        {suffix}
                    </div>
                )}
            </div>
            {error && (
                <span className="text-xs text-red-500 mt-2 inline-flex items-center gap-1">
                    <AlertCircle size={13} />
                    {error}
                </span>
            )}
        </div>
    );
});

export default Input;
