import { ReactNode, useState } from "react";
import { cn } from "../lib/cn";

interface Tab {
  value: string;
  label: string;
  content: ReactNode;
}

interface Props {
  tabs: Tab[];
  initial?: string;
}

export function Tabs({ tabs, initial }: Props) {
  const [active, setActive] = useState(initial ?? tabs[0]?.value);
  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 gap-1 border-b border-nb-gray-200 dark:border-nb-gray-800">
        {tabs.map((t) => (
          <button
            key={t.value}
            onClick={() => setActive(t.value)}
            className={cn(
              "border-b-2 px-3 py-2 text-sm font-medium transition-colors",
              active === t.value
                ? "border-netbird text-netbird"
                : "border-transparent text-nb-gray-500 hover:text-nb-gray-800 dark:hover:text-nb-gray-200",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-auto">
        {tabs.find((t) => t.value === active)?.content}
      </div>
    </div>
  );
}
