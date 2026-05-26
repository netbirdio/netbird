import { useRef, useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import { cn } from "@/lib/cn";

type CopyToClipboardProps = {
    children: ReactNode;
    message?: string;
    size?: number;
    iconAlignment?: "left" | "right";
    className?: string;
    alwaysShowIcon?: boolean;
};

export const CopyToClipboard = ({
    children,
    message,
    size = 10,
    iconAlignment = "right",
    className,
    alwaysShowIcon = false,
}: CopyToClipboardProps) => {
    const wrapperRef = useRef<HTMLDivElement>(null);
    const [copied, setCopied] = useState(false);

    const handleClick = async (e: React.MouseEvent) => {
        e.stopPropagation();
        e.preventDefault();
        const text = message ?? wrapperRef.current?.innerText ?? "";
        if (!text) return;
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 500);
        } catch {
            //
        }
    };

    return (
        <div
            ref={wrapperRef}
            onClick={handleClick}
            className={cn(
                "inline-flex gap-2 items-center group/copy cursor-pointer wails-no-draggable",
                className,
            )}
        >
            <span className={cn("relative truncate min-w-0")}>
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
        </div>
    );
};
