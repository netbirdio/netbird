import { cn } from "@/utils/helpers";

type Props = {
  children: React.ReactNode;
  className?: string;
};

export function Description({ children, className }: Readonly<Props>) {
  return (
    <div className={cn("text-sm text-nb-gray-300 font-light mt-2 block text-center z-10 relative", className)}>
      {children}
    </div>
  );
}