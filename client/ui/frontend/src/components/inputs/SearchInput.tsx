import { forwardRef, type InputHTMLAttributes, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { SearchIcon } from "lucide-react";
import { cn } from "@/lib/cn";

type Props = InputHTMLAttributes<HTMLInputElement> & {
    iconSize?: number;
    shortcut?: ReactNode;
};

export const SearchInput = forwardRef<HTMLInputElement, Props>(function SearchInput(
    { iconSize = 16, className, disabled, shortcut, "aria-label": ariaLabel, ...props },
    ref,
) {
    const { t } = useTranslation();
    return (
        <div
            role={"search"}
            className={cn("flex h-10 items-center gap-2 px-1", disabled && "opacity-50")}
        >
            <SearchIcon
                size={iconSize}
                aria-hidden={"true"}
                className={"shrink-0 text-nb-gray-300"}
            />
            <input
                ref={ref}
                type={"search"}
                disabled={disabled}
                aria-label={ariaLabel ?? props.placeholder ?? t("common.search")}
                autoCorrect={"off"}
                autoCapitalize={"off"}
                spellCheck={false}
                {...props}
                className={cn(
                    "w-full bg-transparent text-sm text-nb-gray-200 placeholder:text-nb-gray-400",
                    "border-none outline-none",
                    disabled && "cursor-not-allowed",
                    className,
                )}
            />
            {shortcut && (
                <span
                    aria-hidden={"true"}
                    className={cn(
                        "shrink-0 select-none",
                        "inline-flex items-center justify-center",
                        "h-5 min-w-[20px] rounded px-1.5",
                        "border border-nb-gray-850 bg-nb-gray-920",
                        "text-[10px] font-medium text-nb-gray-400",
                        "wails-no-draggable",
                    )}
                >
                    {shortcut}
                </span>
            )}
        </div>
    );
});
