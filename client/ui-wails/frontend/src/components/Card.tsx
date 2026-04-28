import { HTMLAttributes } from "react";
import { cn } from "../lib/cn";

export function Card({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "rounded-lg border border-nb-gray-200 bg-white p-4 dark:border-nb-gray-800 dark:bg-nb-gray-925",
        className,
      )}
      {...rest}
    />
  );
}
