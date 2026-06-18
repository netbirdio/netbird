import { forwardRef, type HTMLAttributes } from "react";
import { ArrowUpCircleIcon } from "lucide-react";
import { cn } from "@/lib/cn";

type Props = HTMLAttributes<HTMLDivElement> & {
    size?: number;
};

export const UpdateBadge = forwardRef<HTMLDivElement, Props>(function UpdateBadge(
    { size = 15, className, ...rest },
    ref,
) {
    return (
        <div
            ref={ref}
            className={cn("relative flex items-center justify-center", className)}
            {...rest}
        >
            <span
                className={
                    "pointer-events-none absolute inline-flex h-[15px] w-[15px] animate-ping rounded-full bg-netbird opacity-20"
                }
            />
            <ArrowUpCircleIcon size={size} className={"text-netbird"} />
        </div>
    );
});
