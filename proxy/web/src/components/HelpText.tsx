import { cn } from "@/utils/helpers";

interface HelpTextProps {
  children?: React.ReactNode;
  className?: string;
}

export default function HelpText({ children, className }: Readonly<HelpTextProps>) {
  return (
    <span
      className={cn(
        "text-[.8rem] text-nb-gray-300 block font-light tracking-wide",
        className
      )}
    >
      {children}
    </span>
  );
}
