import { cn } from "@/utils/helpers";
import { useState, useMemo, useCallback } from "react";
import { TabContext, useTabContext } from "./TabContext";

type TabsProps = {
  value?: string;
  defaultValue?: string;
  onChange?: (value: string) => void;
  children:
    | React.ReactNode
    | ((context: { value: string; onChange: (value: string) => void }) => React.ReactNode);
};

function SegmentedTabs({ value, defaultValue, onChange, children }: Readonly<TabsProps>) {
  const [internalValue, setInternalValue] = useState(defaultValue ?? "");
  const currentValue = value ?? internalValue;

  const handleChange = useCallback((newValue: string) => {
    if (value === undefined) {
      setInternalValue(newValue);
    }
    onChange?.(newValue);
  }, [value, onChange]);

  const contextValue = useMemo(
    () => ({ value: currentValue, onChange: handleChange }),
    [currentValue, handleChange],
  );

  return (
    <TabContext.Provider value={contextValue}>
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
}: Readonly<{
  children: React.ReactNode;
  className?: string;
}>) {
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
}: Readonly<{
  children: React.ReactNode;
  value: string;
  disabled?: boolean;
  className?: string;
  selected?: boolean;
  onClick?: () => void;
}>) {
  const context = useTabContext();
  const isSelected = selected ?? value === context.value;

  let stateClassName = "";
  if (isSelected) {
    stateClassName = "bg-nb-gray-900 text-white";
  } else if (!disabled) {
    stateClassName = "text-nb-gray-400 hover:bg-nb-gray-900/50";
  }

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
        stateClassName,
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
}: Readonly<{
  children: React.ReactNode;
  value: string;
  className?: string;
  visible?: boolean;
}>) {
  const context = useTabContext();
  const isVisible = visible ?? value === context.value;

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
