import { cva, VariantProps } from "class-variance-authority";
import { Check, Copy } from "lucide-react";
import { ButtonHTMLAttributes, forwardRef, useState } from "react";

import { cn } from "@/lib/cn";

type ButtonVariants = VariantProps<typeof buttonVariants>;

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement>, ButtonVariants {
    disabled?: boolean;
    stopPropagation?: boolean;
    copy?: string;
}

const buttonVariants = cva(
    [
        "relative",
        "text-sm focus:z-10 focus:ring-2 font-semibold focus:outline-none whitespace-nowrap shadow-sm select-none",
        "inline-flex gap-2 items-center justify-center transition-colors focus:ring-offset-1",
        "disabled:opacity-40 disabled:cursor-not-allowed disabled:dark:text-nb-gray-300 dark:ring-offset-neutral-950/50",
    ],
    {
        variants: {
            variant: {
                default: [
                    "bg-white hover:text-black focus:ring-zinc-200/50 hover:bg-gray-100 border-gray-200 text-gray-900",
                    "dark:focus:ring-zinc-800/50 dark:bg-nb-gray dark:text-gray-400 dark:border-gray-700/30 dark:hover:text-white dark:hover:bg-zinc-800/50",
                ],
                primary: [
                    "dark:focus:ring-netbird-600/50 dark:ring-offset-neutral-950/50 enabled:dark:bg-netbird disabled:dark:bg-nb-gray-900 dark:text-gray-100 enabled:dark:hover:text-white enabled:dark:hover:bg-netbird-500/80",
                    "enabled:bg-netbird enabled:text-white enabled:focus:ring-netbird-400/50 enabled:hover:bg-netbird-500",
                ],
                secondary: [
                    "bg-white hover:text-black focus:ring-zinc-200/50 hover:bg-gray-100 border-gray-200 text-gray-900",
                    "dark:ring-offset-neutral-950/50 dark:focus:ring-neutral-500/20",
                    "dark:bg-nb-gray-920 dark:text-gray-400 dark:border-gray-700/40 dark:hover:text-white dark:hover:bg-nb-gray-910",
                ],
                secondaryLighter: [
                    "bg-white hover:text-black focus:ring-zinc-200/50 hover:bg-gray-100 border-gray-200 text-gray-900",
                    "dark:ring-offset-neutral-950/50 dark:focus:ring-neutral-500/20",
                    "dark:bg-nb-gray-900/70 dark:text-gray-400 dark:border-gray-700/70 dark:hover:text-white dark:hover:bg-nb-gray-800/60",
                ],
                subtle: [
                    "bg-nb-gray-50 hover:bg-nb-gray-100 focus:ring-nb-gray-200/60 border-nb-gray-200 text-nb-gray-900",
                    "dark:ring-offset-neutral-950/50 dark:focus:ring-nb-gray-200/40",
                    "dark:bg-nb-gray-50 dark:text-nb-gray-900 dark:border-nb-gray-200 dark:hover:bg-nb-gray-100 dark:hover:text-nb-gray-950",
                ],
                input: [
                    "bg-white hover:text-black focus:ring-zinc-200/50 hover:bg-gray-100 border-neutral-200 text-gray-900",
                    "dark:ring-offset-neutral-950/50 dark:focus:ring-neutral-500/20",
                    "dark:bg-nb-gray-900 dark:text-gray-400 dark:border-nb-gray-700 dark:hover:bg-nb-gray-900/80",
                ],
                dropdown: [
                    "bg-white hover:text-black focus:ring-zinc-200/50 hover:bg-gray-100 border-neutral-200 text-gray-900",
                    "dark:ring-offset-neutral-950/50 dark:focus:ring-neutral-500/20",
                    "dark:bg-nb-gray-900/40 dark:text-gray-400 dark:border-nb-gray-900 dark:hover:bg-nb-gray-900/50",
                ],
                dotted: [
                    "bg-white hover:text-black focus:ring-zinc-200/50 hover:bg-gray-100 border-gray-200 text-gray-900 border-dashed",
                    "dark:ring-offset-neutral-950/50 dark:focus:ring-neutral-500/20",
                    "dark:bg-nb-gray-900/30 dark:text-gray-400 dark:border-gray-500/40 dark:hover:text-white dark:hover:bg-nb-gray-900/50",
                ],
                tertiary: [
                    "bg-white hover:text-black focus:ring-zinc-200/50 hover:bg-gray-100 border-gray-200 text-gray-900",
                    "dark:focus:ring-zinc-800/50 dark:bg-white dark:text-gray-800 dark:border-gray-700/40 dark:hover:bg-neutral-200 disabled:dark:bg-nb-gray-920 disabled:dark:text-nb-gray-300",
                ],
                white: [
                    "focus:ring-white/50 bg-white text-gray-800 border-white outline-none hover:bg-neutral-200 disabled:dark:bg-nb-gray-920 disabled:dark:text-nb-gray-300",
                    "disabled:dark:bg-nb-gray-900 disabled:dark:text-nb-gray-300 disabled:dark:border-nb-gray-900",
                ],
                outline: [
                    "bg-white hover:text-black focus:ring-zinc-200/50 hover:bg-gray-100 border-gray-200 text-gray-900",
                    "dark:focus:ring-zinc-800/50 dark:bg-transparent dark:text-netbird dark:border-netbird dark:hover:bg-nb-gray-900/30",
                ],
                "danger-outline": [
                    "enabled:dark:focus:ring-red-800/20 enabled:dark:focus:bg-red-950/40 enabled:hover:dark:bg-red-950/50 enabled:dark:hover:border-red-800/50 dark:bg-transparent dark:text-red-500",
                ],
                "danger-text": [
                    "dark:bg-transparent dark:text-red-500 dark:hover:text-red-600 dark:border-transparent !px-0 !shadow-none !py-0 focus:ring-red-500/30 dark:ring-offset-neutral-950/50 rounded-sm",
                ],
                "default-outline": [
                    "dark:ring-offset-nb-gray-950/50 dark:focus:ring-nb-gray-500/20",
                    "dark:bg-transparent dark:text-nb-gray-400 dark:border-transparent dark:hover:text-white dark:hover:bg-nb-gray-900/30 dark:hover:border-nb-gray-800/50",
                    "data-[state=open]:dark:text-white data-[state=open]:dark:bg-nb-gray-900/30 data-[state=open]:dark:border-nb-gray-800/50",
                ],
                ghost: [
                    "dark:ring-offset-nb-gray-950/50 dark:focus:ring-nb-gray-500/20",
                    "dark:bg-transparent dark:text-nb-gray-400 dark:border-transparent dark:hover:text-white dark:hover:bg-nb-gray-900/30",
                ],
                danger: [
                    "dark:focus:ring-red-700/20 dark:focus:bg-red-700 hover:dark:bg-red-700 dark:hover:border-red-800/50 dark:bg-red-600 dark:text-red-100",
                ],
            },
            size: {
                xs: "text-xs py-2.5 px-3.5",
                xs2: "text-[0.78rem] py-2 px-4",
                sm: "text-sm py-[9px] px-4",
                md: "text-md py-[9px] px-4",
                lg: "text-lg py-[9px] px-4",
            },
            rounded: {
                true: "rounded-md",
                false: "",
            },
            border: {
                0: "border",
                1: "border border-transparent",
                2: "border border-t-0 border-b-0",
            },
        },
    },
);

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
    {
        variant = "default",
        rounded = true,
        border = 1,
        size = "md",
        stopPropagation = true,
        type = "button",
        children,
        className,
        onClick,
        disabled,
        copy,
        ...props
    },
    ref,
) {
    const [copied, setCopied] = useState(false);
    const iconSize = size === "xs" ? 12 : 14;
    return (
        <button
            ref={ref}
            type={type}
            disabled={disabled}
            className={cn(
                buttonVariants({
                    variant,
                    rounded,
                    border: border ? 1 : 0,
                    size,
                }),
                className,
            )}
            onClick={(e) => {
                if (stopPropagation) e.stopPropagation();
                if (copy !== undefined) {
                    void navigator.clipboard
                        .writeText(copy)
                        .then(() => {
                            setCopied(true);
                            setTimeout(() => setCopied(false), 1500);
                        })
                        .catch(() => {});
                }
                onClick?.(e);
            }}
            {...props}
        >
            {copy !== undefined && (copied ? <Check size={iconSize} /> : <Copy size={iconSize} />)}
            {children}
        </button>
    );
});

export default Button;
