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
    const switchId = React.useId();
    const descriptionId = React.useId();

    if (loading) {
        const shimmer =
            "text-transparent select-none rounded bg-[#25282d] box-decoration-clone animate-pulse";
        return (
            <div
                role={"status"}
                aria-busy={"true"}
                aria-live={"polite"}
                className={cn("inline-block w-full text-left", className)}
            >
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
                            aria-hidden={"true"}
                            className={"h-[24px] w-[44px] animate-pulse rounded-full bg-[#25282d]"}
                        />
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div
            {...(disabled ? { inert: "" } : {})}
            className={cn(
                "relative z-[1] cursor-default transition-all duration-300",
                "inline-block w-full text-left",
                disabled && "pointer-events-none opacity-30",
                className,
            )}
        >
            <div className={"flex justify-between gap-10"}>
                <div className={cn(textWrapperClassName)}>
                    <Label htmlFor={switchId} className={labelClassName}>
                        {label}
                    </Label>
                    <HelpText margin={false}>
                        <span id={descriptionId}>{helpText}</span>
                    </HelpText>
                </div>
                <div className={"mt-2 pr-1"}>
                    <ToggleSwitch
                        id={switchId}
                        checked={value}
                        onCheckedChange={onChange}
                        disabled={disabled}
                        dataCy={dataCy}
                        aria-describedby={helpText ? descriptionId : undefined}
                    />
                </div>
            </div>
            {children && value ? <div className={"mt-4"}>{children}</div> : null}
        </div>
    );
}
