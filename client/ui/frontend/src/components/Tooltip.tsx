import { ReactNode, useRef, useState } from "react";
import * as RTooltip from "@radix-ui/react-tooltip";
import { cn } from "@/lib/cn";

type Props = {
    content: ReactNode;
    children: ReactNode;
    side?: RTooltip.TooltipContentProps["side"];
    align?: RTooltip.TooltipContentProps["align"];
    delayDuration?: number;
    sideOffset?: number;
    interactive?: boolean;
    keepOpenOnClick?: boolean;
};

export const Tooltip = ({
    content,
    children,
    side = "bottom",
    align = "center",
    delayDuration = 200,
    sideOffset = 6,
    interactive = false,
    keepOpenOnClick = true,
}: Props) => {
    const [open, setOpen] = useState(false);
    const hoveringRef = useRef(false);

    const handleOpenChange = (next: boolean) => {
        if (!next && keepOpenOnClick && hoveringRef.current) return;
        setOpen(next);
    };

    return (
        <RTooltip.Provider
            delayDuration={delayDuration}
            disableHoverableContent={!interactive}
        >
            <RTooltip.Root open={open} onOpenChange={handleOpenChange}>
                <RTooltip.Trigger
                    asChild
                    onPointerEnter={() => {
                        hoveringRef.current = true;
                    }}
                    onPointerLeave={() => {
                        hoveringRef.current = false;
                        setOpen(false);
                    }}
                >
                    {children}
                </RTooltip.Trigger>
                <RTooltip.Portal>
                    <RTooltip.Content
                        side={side}
                        align={align}
                        sideOffset={sideOffset}
                        onPointerDownOutside={
                            interactive ? undefined : (e) => e.preventDefault()
                        }
                        className={cn(
                            "z-50 select-none rounded-md border border-nb-gray-850 bg-nb-gray-900 px-2 py-1",
                            "text-xs text-nb-gray-100 shadow-lg",
                            "data-[state=delayed-open]:animate-in data-[state=closed]:animate-out",
                            "data-[state=closed]:fade-out-0 data-[state=delayed-open]:fade-in-0",
                            !interactive && "pointer-events-none",
                        )}
                    >
                        {content}
                    </RTooltip.Content>
                </RTooltip.Portal>
            </RTooltip.Root>
        </RTooltip.Provider>
    );
};
