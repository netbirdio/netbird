import { cn } from "../lib/cn";

interface Props {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  label?: string;
  description?: string;
}

export function Switch({ checked, onChange, disabled, label, description }: Props) {
  return (
    <label className={cn("flex items-start gap-3", disabled && "opacity-60")}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cn(
          "mt-0.5 inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors",
          checked ? "bg-netbird" : "bg-nb-gray-300 dark:bg-nb-gray-700",
        )}
      >
        <span
          className={cn(
            "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
            checked ? "translate-x-4" : "translate-x-0.5",
          )}
        />
      </button>
      {(label || description) && (
        <span className="flex flex-col">
          {label && <span className="text-sm font-medium">{label}</span>}
          {description && (
            <span className="text-xs text-nb-gray-500">{description}</span>
          )}
        </span>
      )}
    </label>
  );
}
