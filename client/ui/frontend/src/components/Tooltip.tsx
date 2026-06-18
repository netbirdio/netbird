import { type ReactNode, useEffect, useRef, useState } from "react";
import * as RTooltip from "@radix-ui/react-tooltip";
import { cn } from "@/lib/cn";

type Props = {
    content: ReactNode;
    children: ReactNode;
    side?: RTooltip.TooltipContentProps["side"];
    align?: RTooltip.TooltipContentProps["align"];
    delayDuration?: number;
    sideOffset?: number;
    alignOffset?: number;
    interactive?: boolean;
    keepOpenOnClick?: boolean;
    contentClassName?: string;
    closeDelay?: number;
};

export const Tooltip = ({
    content,
    children,
    side = "bottom",
    align = "center",
    delayDuration = 200,
    sideOffset = 6,
    alignOffset = 0,
    interactive = false,
    keepOpenOnClick = true,
    contentClassName,
    closeDelay = 0,
}: Props) => {
    const [open, setOpen] = useState(false);
    const hoveringRef = useRef(false);
    const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

    const cancelClose = () => {
        if (closeTimer.current) {
            clearTimeout(closeTimer.current);
            closeTimer.current = null;
        }
    };
    const scheduleClose = () => {
        cancelClose();
        if (closeDelay <= 0) {
            setOpen(false);
            return;
        }
        closeTimer.current = setTimeout(() => setOpen(false), closeDelay);
    };
    useEffect(() => () => cancelClose(), []);

    const handleOpenChange = (next: boolean) => {
        if (!next && keepOpenOnClick && hoveringRef.current) return;
        if (next) cancelClose();
        setOpen(next);
    };

    return (
        <RTooltip.Provider delayDuration={delayDuration} disableHoverableContent={!interactive}>
            <RTooltip.Root open={open} onOpenChange={handleOpenChange}>
                <RTooltip.Trigger
                    asChild
                    onPointerEnter={() => {
                        hoveringRef.current = true;
                        cancelClose();
                    }}
                    onPointerLeave={() => {
                        hoveringRef.current = false;
                        scheduleClose();
                    }}
                >
                    {children}
                </RTooltip.Trigger>
                <RTooltip.Portal>
                    <RTooltip.Content
                        side={side}
                        align={align}
                        sideOffset={sideOffset}
                        alignOffset={alignOffset}
                        onPointerEnter={interactive ? cancelClose : undefined}
                        onPointerLeave={interactive ? scheduleClose : undefined}
                        onPointerDownOutside={interactive ? undefined : (e) => e.preventDefault()}
                        className={cn(
                            "z-50 select-none text-xs text-nb-gray-100 shadow-lg",
                            "data-[state=delayed-open]:animate-in data-[state=closed]:animate-out",
                            "data-[state=closed]:fade-out-0 data-[state=delayed-open]:fade-in-0",
                            !interactive && "pointer-events-none",
                            contentClassName ??
                                "rounded-md border border-nb-gray-850 bg-nb-gray-900 px-2 py-1",
                        )}
                    >
                        {content}
                    </RTooltip.Content>
                </RTooltip.Portal>
            </RTooltip.Root>
        </RTooltip.Provider>
    );
};
