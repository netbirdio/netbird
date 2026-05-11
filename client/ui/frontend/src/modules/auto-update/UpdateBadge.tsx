import { ArrowUpCircleIcon } from "lucide-react";
import { cn } from "@/lib/cn";

type Props = {
    size?: number;
    className?: string;
};

export const UpdateBadge = ({ size = 15, className }: Props) => {
    return (
        <div className={cn("relative flex items-center justify-center", className)}>
            <span
                className={
                    "animate-ping absolute inline-flex h-[15px] w-[15px] rounded-full bg-netbird opacity-20 pointer-events-none"
                }
            />
            <ArrowUpCircleIcon size={size} className={"text-netbird"} />
        </div>
    );
};
