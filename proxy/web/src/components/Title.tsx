import { cn } from "@/utils/helpers";

type Props = {
  children: React.ReactNode;
  className?: string;
};

export function Title({ children, className }: Readonly<Props>) {
  return (
    <h1 className={cn("text-xl! text-center z-10 relative", className)}>
      {children}
    </h1>
  );
}
