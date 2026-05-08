import { ReactNode } from "react";
import { cn } from "@/lib/cn.ts";

type Props = {
    children: ReactNode;
};

export const MainRightSide = ({ children }: Props) => {
    return (
        <div
            className={cn(
                "wails-no-draggable",
                "bg-nb-gray-935 border border-nb-gray-910",
                "flex-1 min-h-0 min-w-0 flex flex-col  rounded-xl rounded-br-2xl overflow-hidden",
            )}
        >
            {children}
        </div>
    );
};
