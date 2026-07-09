import { cva, type VariantProps } from "class-variance-authority";
import { Check, Copy, Loader2 } from "lucide-react";
import { type ButtonHTMLAttributes, forwardRef, useEffect, useRef, useState } from "react";

import { cn } from "@/lib/cn";

type ButtonVariants = VariantProps<typeof buttonVariants>;

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement>, ButtonVariants {
    disabled?: boolean;
    stopPropagation?: boolean;
    copy?: string;
    loading?: boolean;
}

const buttonVariants = cva(
    [
        "relative",
        "cursor-default select-none whitespace-nowrap text-sm font-medium shadow-sm focus:z-10 focus:outline-none focus:ring-2",
        "inline-flex items-center justify-center gap-2 transition-colors focus:ring-offset-1",
        "disabled:cursor-not-allowed disabled:opacity-40 dark:ring-offset-neutral-950/50 disabled:dark:text-nb-gray-300",
    ],
    {
        variants: {
            variant: {
                default: [
                    "border-gray-200 bg-white text-gray-900 hover:bg-gray-100 hover:text-black focus:ring-zinc-200/50",
                    "dark:border-gray-700/30 dark:bg-nb-gray dark:text-gray-400 dark:hover:bg-zinc-800/50 dark:hover:text-white dark:focus:ring-zinc-800/50",
                ],
                primary: [
                    "dark:text-gray-100 dark:ring-offset-neutral-950/50 dark:focus:ring-netbird-600/50 enabled:dark:bg-netbird enabled:dark:hover:bg-netbird-500/80 enabled:dark:hover:text-white disabled:dark:bg-nb-gray-900",
                    "enabled:bg-netbird enabled:text-white enabled:hover:bg-netbird-500 enabled:focus:ring-netbird-400/50",
                ],
                secondary: [
                    "border-gray-200 bg-white text-gray-900 hover:bg-gray-100 hover:text-black focus:ring-zinc-200/50",
                    "dark:ring-offset-neutral-950/50 dark:focus:ring-neutral-500/20",
                    "dark:border-gray-700/40 dark:bg-nb-gray-920 dark:text-gray-400 dark:hover:bg-nb-gray-910 dark:hover:text-white",
                ],
                secondaryLighter: [
                    "border-gray-200 bg-white text-gray-900 hover:bg-gray-100 hover:text-black focus:ring-zinc-200/50",
                    "dark:ring-offset-neutral-950/50 dark:focus:ring-neutral-500/20",
                    "dark:border-gray-700/70 dark:bg-nb-gray-900/70 dark:text-gray-400 dark:hover:bg-nb-gray-800/60 dark:hover:text-white",
                ],
                subtle: [
                    "border-nb-gray-200 bg-nb-gray-50 text-nb-gray-900 hover:bg-nb-gray-100 focus:ring-nb-gray-200/60",
                    "dark:ring-offset-neutral-950/50 dark:focus:ring-nb-gray-200/40",
                    "dark:border-nb-gray-200 dark:bg-nb-gray-50 dark:text-nb-gray-900 dark:hover:bg-nb-gray-100 dark:hover:text-nb-gray-950",
                ],
                input: [
                    "border-neutral-200 bg-white text-gray-900 hover:bg-gray-100 hover:text-black focus:ring-zinc-200/50",
                    "dark:ring-offset-neutral-950/50 dark:focus:ring-neutral-500/20",
                    "dark:border-nb-gray-700 dark:bg-nb-gray-900 dark:text-gray-400 dark:hover:bg-nb-gray-900/80",
                ],
                dropdown: [
                    "border-neutral-200 bg-white text-gray-900 hover:bg-gray-100 hover:text-black focus:ring-zinc-200/50",
                    "dark:ring-offset-neutral-950/50 dark:focus:ring-neutral-500/20",
                    "dark:border-nb-gray-900 dark:bg-nb-gray-900/40 dark:text-gray-400 dark:hover:bg-nb-gray-900/50",
                ],
                dotted: [
                    "border-dashed border-gray-200 bg-white text-gray-900 hover:bg-gray-100 hover:text-black focus:ring-zinc-200/50",
                    "dark:ring-offset-neutral-950/50 dark:focus:ring-neutral-500/20",
                    "dark:border-gray-500/40 dark:bg-nb-gray-900/30 dark:text-gray-400 dark:hover:bg-nb-gray-900/50 dark:hover:text-white",
                ],
                tertiary: [
                    "border-gray-200 bg-white text-gray-900 hover:bg-gray-100 hover:text-black focus:ring-zinc-200/50",
                    "dark:border-gray-700/40 dark:bg-white dark:text-gray-800 dark:hover:bg-neutral-200 dark:focus:ring-zinc-800/50 disabled:dark:bg-nb-gray-920 disabled:dark:text-nb-gray-300",
                ],
                white: [
                    "border-white bg-white text-gray-800 outline-none hover:bg-neutral-200 focus:ring-white/50 disabled:dark:bg-nb-gray-920 disabled:dark:text-nb-gray-300",
                    "disabled:dark:border-nb-gray-900 disabled:dark:bg-nb-gray-900 disabled:dark:text-nb-gray-300",
                ],
                outline: [
                    "border-gray-200 bg-white text-gray-900 hover:bg-gray-100 hover:text-black focus:ring-zinc-200/50",
                    "dark:border-netbird dark:bg-transparent dark:text-netbird dark:hover:bg-nb-gray-900/30 dark:focus:ring-zinc-800/50",
                ],
                "danger-outline": [
                    "dark:bg-transparent dark:text-red-500 enabled:dark:hover:border-red-800/50 enabled:hover:dark:bg-red-950/50 enabled:dark:focus:bg-red-950/40 enabled:dark:focus:ring-red-800/20",
                ],
                "danger-text": [
                    "rounded-sm !px-0 !py-0 !shadow-none focus:ring-red-500/30 dark:border-transparent dark:bg-transparent dark:text-red-500 dark:ring-offset-neutral-950/50 dark:hover:text-red-600",
                ],
                "default-outline": [
                    "dark:ring-offset-nb-gray-950/50 dark:focus:ring-nb-gray-500/20",
                    "dark:border-transparent dark:bg-transparent dark:text-nb-gray-400 dark:hover:border-nb-gray-800/50 dark:hover:bg-nb-gray-900/30 dark:hover:text-white",
                    "data-[state=open]:dark:border-nb-gray-800/50 data-[state=open]:dark:bg-nb-gray-900/30 data-[state=open]:dark:text-white",
                ],
                ghost: [
                    "dark:ring-offset-nb-gray-950/50 dark:focus:ring-nb-gray-500/20",
                    "dark:border-transparent dark:bg-transparent dark:text-nb-gray-400 dark:hover:bg-nb-gray-900/30 dark:hover:text-white",
                ],
                danger: [
                    "dark:bg-red-600 dark:text-red-100 dark:hover:border-red-800/50 hover:dark:bg-red-700 dark:focus:bg-red-700 dark:focus:ring-red-700/20",
                ],
            },
            size: {
                xs: "px-3.5 py-2.5 text-xs",
                xs2: "px-4 py-[1.1rem] text-[0.78rem] leading-[0]",
                sm: "px-4 py-[9px] text-sm",
                md: "px-4 py-[9px]",
                lg: "px-4 py-[9px] text-lg",
            },
            rounded: {
                true: "rounded-md",
                false: "",
            },
            border: {
                0: "border",
                1: "border border-transparent",
                2: "border border-b-0 border-t-0",
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
        loading = false,
        ...props
    },
    ref,
) {
    const [copied, setCopied] = useState(false);
    const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
    useEffect(
        () => () => {
            if (copyTimer.current) clearTimeout(copyTimer.current);
        },
        [],
    );
    const iconSize = size === "xs" ? 12 : 14;
    return (
        <button
            ref={ref}
            type={type}
            tabIndex={0}
            disabled={disabled || loading}
            aria-busy={loading || undefined}
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
                            if (copyTimer.current) clearTimeout(copyTimer.current);
                            copyTimer.current = setTimeout(() => setCopied(false), 1500);
                        })
                        .catch((e: unknown) => console.warn("copy to clipboard failed", e));
                }
                onClick?.(e);
            }}
            {...props}
        >
            {loading && (
                <span
                    aria-hidden={"true"}
                    className={"absolute inset-0 flex items-center justify-center"}
                >
                    <Loader2 size={iconSize} className={"animate-spin"} />
                </span>
            )}
            <span className={cn("contents", loading && "invisible")}>
                {copy !== undefined &&
                    (copied ? (
                        <Check size={iconSize} aria-hidden={"true"} />
                    ) : (
                        <Copy size={iconSize} aria-hidden={"true"} />
                    ))}
                {children}
            </span>
        </button>
    );
});

export default Button;
