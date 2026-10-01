import { cn } from "@/utils/helpers";
import { GradientFadedBackground } from "@/components/GradientFadedBackground";

export const Card = ({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) => {
  return (
    <div
      className={cn(
        "px-6 sm:px-10 py-10 pt-8",
        "bg-nb-gray-940 border border-nb-gray-910 rounded-lg relative",
        className
      )}
    >
      <GradientFadedBackground />
      {children}
    </div>
  );
};
