import { cn } from "@/utils/helpers";
import { useState } from "react";
import { TabContext, useTabContext } from "./TabContext";

type TabsProps = {
  value?: string;
  defaultValue?: string;
  onChange?: (value: string) => void;
  children:
    | React.ReactNode
    | ((context: { value: string; onChange: (value: string) => void }) => React.ReactNode);
};

function SegmentedTabs({ value, defaultValue, onChange, children }: TabsProps) {
  const [internalValue, setInternalValue] = useState(defaultValue || "");
  const currentValue = value !== undefined ? value : internalValue;

  const handleChange = (newValue: string) => {
    if (value === undefined) {
      setInternalValue(newValue);
    }
    onChange?.(newValue);
  };

  return (
    <TabContext.Provider value={{ value: currentValue, onChange: handleChange }}>
      <div>
        {typeof children === "function"
          ? children({ value: currentValue, onChange: handleChange })
          : children}
      </div>
    </TabContext.Provider>
  );
}

function List({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      role="tablist"
      className={cn(
        "bg-nb-gray-930/70 p-1.5 flex justify-center gap-1 border-nb-gray-900",
        className
      )}
    >
      {children}
    </div>
  );
}

function Trigger({
  children,
  value,
  disabled = false,
  className,
  selected,
  onClick,
}: {
  children: React.ReactNode;
  value: string;
  disabled?: boolean;
  className?: string;
  selected?: boolean;
  onClick?: () => void;
}) {
  const context = useTabContext();
  const isSelected = selected !== undefined ? selected : value === context.value;

  const handleClick = () => {
    context.onChange(value);
    onClick?.();
  };

  return (
    <button
      role="tab"
      type="button"
      disabled={disabled}
      aria-selected={isSelected}
      onClick={handleClick}
      className={cn(
        "px-4 py-2 text-sm rounded-md w-full transition-all cursor-pointer",
        disabled && "opacity-30 cursor-not-allowed",
        isSelected
          ? "bg-nb-gray-900 text-white"
          : disabled
            ? ""
            : "text-nb-gray-400 hover:bg-nb-gray-900/50",
        className
      )}
    >
      <div className="flex items-center w-full justify-center gap-2">
        {children}
      </div>
    </button>
  );
}

function Content({
  children,
  value,
  className,
  visible,
}: {
  children: React.ReactNode;
  value: string;
  className?: string;
  visible?: boolean;
}) {
  const context = useTabContext();
  const isVisible = visible !== undefined ? visible : value === context.value;

  if (!isVisible) return null;

  return (
    <div
      role="tabpanel"
      className={cn(
        "bg-nb-gray-930/70 px-4 pt-4 pb-5 rounded-b-md border border-t-0 border-nb-gray-900",
        className
      )}
    >
      {children}
    </div>
  );
}

SegmentedTabs.List = List;
SegmentedTabs.Trigger = Trigger;
SegmentedTabs.Content = Content;

export { SegmentedTabs };
