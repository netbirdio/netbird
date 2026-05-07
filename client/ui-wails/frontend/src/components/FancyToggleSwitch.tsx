import React from "react";
import { HelpText } from "@/components/HelpText";
import { Label } from "@/components/Label";
import { ToggleSwitch } from "@/components/ToggleSwitch";
import { cn } from "@/lib/cn";

interface Props {
  value: boolean;
  onChange: (value: boolean) => void;
  helpText?: React.ReactNode;
  label?: React.ReactNode;
  children?: React.ReactNode;
  disabled?: boolean;
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
  dataCy,
  className,
  labelClassName,
  textWrapperClassName = "max-w-md",
}: Readonly<Props>) {
  const handleToggle = () => {
    if (disabled) return;
    onChange(!value);
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (disabled) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      handleToggle();
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
        "cursor-pointer transition-all duration-300 relative z-[1]",
        "inline-block text-left w-full",
        disabled && "opacity-50 pointer-events-none",
        className,
      )}
    >
      <div className={"flex justify-between gap-10"}>
        <div className={cn(textWrapperClassName)}>
          <Label className={labelClassName}>{label}</Label>
          <HelpText margin={false}>{helpText}</HelpText>
        </div>
        <div className={"mt-2 pr-1"}>
          <ToggleSwitch
            checked={value}
            onCheckedChange={onChange}
            dataCy={dataCy}
          />
        </div>
      </div>
      {children && value ? (
        <div className="mt-4" onClick={(e) => e.stopPropagation()}>
          {children}
        </div>
      ) : null}
    </div>
  );
}
