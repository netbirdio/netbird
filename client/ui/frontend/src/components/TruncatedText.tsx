import { useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { Tooltip } from "@/components/Tooltip";

type Props = {
    text: string;
    className?: string;
    tooltipContent?: ReactNode;
    delayDuration?: number;
};

export const TruncatedText = ({ text, className, tooltipContent, delayDuration = 600 }: Props) => {
    const ref = useRef<HTMLSpanElement>(null);
    const [overflowing, setOverflowing] = useState(false);

    useLayoutEffect(() => {
        const el = ref.current;
        if (!el) return;
        setOverflowing(el.scrollWidth > el.clientWidth);
    }, [text]);

    const span = (
        <span ref={ref} className={className}>
            {text}
        </span>
    );
    if (!overflowing) return span;
    return (
        <Tooltip content={tooltipContent ?? text} delayDuration={delayDuration}>
            {span}
        </Tooltip>
    );
};
