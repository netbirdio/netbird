import { useEffect, useRef, useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import { cn } from "@/lib/cn";

const VARIANT_HOVER = {
    default: "group-hover/copy:[&_*]:text-nb-gray-300",
    bright: "group-hover/copy:[&_*]:text-nb-gray-200",
} as const;

type CopyToClipboardVariant = keyof typeof VARIANT_HOVER;

type CopyToClipboardProps = {
    children: ReactNode;
    message?: string;
    size?: number;
    iconAlignment?: "left" | "right";
    className?: string;
    iconClassName?: string;
    alwaysShowIcon?: boolean;
    variant?: CopyToClipboardVariant;
};

export const CopyToClipboard = ({
    children,
    message,
    size = 10,
    iconAlignment = "right",
    className,
    iconClassName,
    alwaysShowIcon = false,
    variant = "default",
}: CopyToClipboardProps) => {
    const wrapperRef = useRef<HTMLButtonElement>(null);
    const [copied, setCopied] = useState(false);
    const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
    useEffect(
        () => () => {
            if (copyTimer.current) clearTimeout(copyTimer.current);
        },
        [],
    );

    const handleClick = async (e: React.MouseEvent) => {
        e.stopPropagation();
        e.preventDefault();
        const text = message ?? wrapperRef.current?.innerText ?? "";
        if (!text) return;
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            if (copyTimer.current) clearTimeout(copyTimer.current);
            copyTimer.current = setTimeout(() => setCopied(false), 500);
        } catch (e) {
            console.warn("copy to clipboard failed", e);
        }
    };

    return (
        <button
            type="button"
            ref={wrapperRef}
            onClick={handleClick}
            className={cn(
                "inline-flex gap-2 items-center group/copy cursor-default wails-no-draggable text-left pointer-events-auto",
                className,
            )}
        >
            <span
                className={cn(
                    "relative truncate min-w-0",
                    "[&_*]:transition-colors",
                    VARIANT_HOVER[variant],
                )}
            >
                {children}
                <span
                    className={
                        "absolute bottom-0 left-0 right-0 border-b border-dashed border-transparent group-hover/copy:border-nb-gray-500 pointer-events-none"
                    }
                />
            </span>
            <span
                className={cn(
                    "shrink-0 inline-flex relative top-[2px] right-[1px]",
                    iconAlignment === "left" ? "order-first" : "order-last",
                    iconClassName,
                )}
            >
                <Check
                    size={size}
                    className={cn(
                        "text-nb-gray-100",
                        !copied && "hidden",
                        !alwaysShowIcon && !copied && "opacity-0",
                    )}
                />
                <Copy
                    size={size}
                    className={cn(
                        "text-nb-gray-100 group-hover/copy:opacity-100",
                        copied && "hidden",
                        !alwaysShowIcon && "opacity-0",
                    )}
                />
            </span>
        </button>
    );
};
