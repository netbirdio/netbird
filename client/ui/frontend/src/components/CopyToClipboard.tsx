import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
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
    "aria-label"?: string;
    tabIndex?: number;
    onKeyDown?: (e: KeyboardEvent<HTMLButtonElement>) => void;
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
    "aria-label": ariaLabel,
    tabIndex = 0,
    onKeyDown,
}: CopyToClipboardProps) => {
    const { t } = useTranslation();
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

    const resolvedLabel =
        ariaLabel ?? (message ? `${t("common.copy")} ${message}` : t("common.copy"));

    return (
        <button
            type={"button"}
            ref={wrapperRef}
            onClick={handleClick}
            onKeyDown={onKeyDown}
            tabIndex={tabIndex}
            aria-label={resolvedLabel}
            aria-live={"polite"}
            className={cn(
                "group/copy wails-no-draggable pointer-events-auto inline-flex cursor-default items-center gap-2 rounded-sm text-left outline-none",
                "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                className,
            )}
        >
            <span
                className={cn(
                    "relative min-w-0 truncate",
                    "[&_*]:transition-colors",
                    VARIANT_HOVER[variant],
                )}
            >
                {children}
                <span
                    aria-hidden={"true"}
                    className={
                        "pointer-events-none absolute bottom-0 left-0 right-0 border-b border-dashed border-transparent group-hover/copy:border-nb-gray-500"
                    }
                />
            </span>
            <span
                aria-hidden={"true"}
                className={cn(
                    "relative right-[1px] top-[2px] inline-flex shrink-0",
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
