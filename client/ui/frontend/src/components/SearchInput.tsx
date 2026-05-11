import { forwardRef, InputHTMLAttributes } from "react";
import { SearchIcon } from "lucide-react";
import { cn } from "@/lib/cn";

type Props = InputHTMLAttributes<HTMLInputElement> & {
    iconSize?: number;
};

export const SearchInput = forwardRef<HTMLInputElement, Props>(
    function SearchInput({ iconSize = 16, className, ...props }, ref) {
        return (
            <div className={"flex items-center gap-2 px-1 h-10"}>
                <SearchIcon
                    size={iconSize}
                    className={"text-nb-gray-300 shrink-0"}
                />
                <input
                    ref={ref}
                    type={"text"}
                    {...props}
                    className={cn(
                        "w-full bg-transparent text-sm text-nb-gray-200 placeholder:text-nb-gray-400",
                        "outline-none border-none",
                        className,
                    )}
                />
            </div>
        );
    },
);
