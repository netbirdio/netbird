import { cn } from "@/utils/helpers";

type LabelProps = React.LabelHTMLAttributes<HTMLLabelElement>;

export function Label({ className, htmlFor, ...props }: Readonly<LabelProps>) {
  return (
    <label
      htmlFor={htmlFor}
      className={cn(
        "text-sm font-medium tracking-wider leading-none",
        "peer-disabled:cursor-not-allowed peer-disabled:opacity-70",
        "mb-2.5 inline-block text-nb-gray-200",
        "flex items-center gap-2 select-none",
        className
      )}
      {...props}
    />
  );
}
