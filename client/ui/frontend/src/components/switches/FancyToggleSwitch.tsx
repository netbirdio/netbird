import React from "react";
import { HelpText } from "@/components/typography/HelpText";
import { Label } from "@/components/typography/Label";
import { ToggleSwitch } from "@/components/switches/ToggleSwitch";
import { cn } from "@/lib/cn";

interface Props {
    value: boolean;
    onChange: (value: boolean) => void;
    helpText?: React.ReactNode;
    label?: React.ReactNode;
    children?: React.ReactNode;
    disabled?: boolean;
    loading?: boolean;
    dataCy?: string;
    className?: string;
    labelClassName?: string;
    textWrapperClassName?: string;
}

export default function FancyToggleSwitch({
    value,
    onChange,
    helpText,
    label,
    children,
    disabled = false,
    loading = false,
    dataCy,
    className,
    labelClassName,
    textWrapperClassName = "max-w-lg",
}: Readonly<Props>) {
    const childrenRef = React.useRef<HTMLDivElement>(null);

    if (loading) {
        const shimmer =
            "text-transparent select-none rounded bg-[#25282d] box-decoration-clone animate-pulse";
        return (
            <div className={cn("inline-block text-left w-full", className)} aria-busy>
                <div className={"flex justify-between gap-10"}>
                    <div className={cn(textWrapperClassName)}>
                        <Label className={labelClassName}>
                            <span className={shimmer}>{label}</span>
                        </Label>
                        <HelpText margin={false}>
                            <span className={cn(shimmer, "text-[0.6rem] leading-relaxed")}>
                                {helpText}
                            </span>
                        </HelpText>
                    </div>
                    <div className={"mt-2 pr-1"}>
                        <div
                            className={"h-[24px] w-[44px] rounded-full bg-[#25282d] animate-pulse"}
                        />
                    </div>
                </div>
            </div>
        );
    }

    const fromChildren = (target: EventTarget | null) =>
        target instanceof Node && childrenRef.current?.contains(target);

    const handleToggle = (event: React.MouseEvent) => {
        if (disabled || fromChildren(event.target)) return;
        onChange(!value);
    };

    const handleKeyDown = (event: React.KeyboardEvent) => {
        if (disabled || fromChildren(event.target)) return;
        if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onChange(!value);
        }
    };

    return (
        <div
            onClick={handleToggle}
            onKeyDown={handleKeyDown}
            tabIndex={-1}
            role={"switch"}
            aria-checked={value}
            className={cn(
                "cursor-default transition-all duration-300 relative z-[1]",
                "inline-block text-left w-full",
                disabled && "opacity-30 pointer-events-none",
                className,
            )}
        >
            <div className={"flex justify-between gap-10"}>
                <div className={cn(textWrapperClassName)}>
                    <Label className={labelClassName}>{label}</Label>
                    <HelpText margin={false}>{helpText}</HelpText>
                </div>
                <div className={"mt-2 pr-1"}>
                    <ToggleSwitch checked={value} onCheckedChange={onChange} dataCy={dataCy} />
                </div>
            </div>
            {children && value ? (
                <div className="mt-4" ref={childrenRef}>
                    {children}
                </div>
            ) : null}
        </div>
    );
}
