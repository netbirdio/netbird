import { ReactNode, useEffect } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import { cn } from "@/lib/cn";

type Props = {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    children?: ReactNode;
    className?: string;
};

export const BottomSheet = ({ open, onOpenChange, children, className }: Props) => {
    useEffect(() => {
        if (!open) return;
        const onKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") onOpenChange(false);
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [open, onOpenChange]);

    return createPortal(
        <AnimatePresence>
            {open && (
                <div className={"fixed inset-0 z-50"}>
                    <motion.div
                        className={"absolute inset-0 bg-black/40 backdrop-blur-sm"}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.18, ease: "easeOut" }}
                        onClick={() => onOpenChange(false)}
                    />
                    <motion.div
                        role={"dialog"}
                        aria-modal={"true"}
                        className={cn(
                            "absolute left-0 right-0 bottom-0",
                            "bg-nb-gray-925 border-t border-nb-gray-850 rounded-t-2xl",
                            "shadow-2xl outline-none",
                            "max-h-[85vh] overflow-hidden",
                            className,
                        )}
                        initial={{ y: "100%" }}
                        animate={{ y: 0 }}
                        exit={{ y: "100%" }}
                        transition={{ type: "spring", stiffness: 360, damping: 34 }}
                    >
                        <div className={"flex justify-center pt-2"}>
                            <div className={"h-1 w-10 rounded-full bg-nb-gray-700"} />
                        </div>
                        <div className={"px-5 pt-4 pb-6"}>{children}</div>
                    </motion.div>
                </div>
            )}
        </AnimatePresence>,
        document.body,
    );
};
