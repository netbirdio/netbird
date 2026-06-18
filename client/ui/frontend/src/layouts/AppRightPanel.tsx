import { type ReactNode } from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/cn.ts";

type Props = {
    children: ReactNode;
    overlay?: ReactNode;
    overlayOpen?: boolean;
    className?: string;
};

const PANEL_TRANSITION = {
    duration: 0.32,
    ease: [0.32, 0.72, 0, 1] as [number, number, number, number],
};

export const AppRightPanel = ({ children, overlay, overlayOpen = false, className }: Props) => {
    return (
        <div
            className={cn(
                "wails-no-draggable relative m-5",
                "border border-nb-gray-920 bg-nb-gray-940",
                "flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-xl rounded-br-2xl",
                className,
            )}
        >
            <motion.div
                animate={{ x: overlayOpen ? -48 : 0 }}
                transition={PANEL_TRANSITION}
                className={"flex min-h-0 min-w-0 flex-1 flex-col"}
                style={{ pointerEvents: overlayOpen ? "none" : "auto" }}
            >
                {children}
            </motion.div>
            {overlay}
        </div>
    );
};
