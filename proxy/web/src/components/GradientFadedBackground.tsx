import { cn } from "@/utils/helpers";

type Props = {
  className?: string;
};

export const GradientFadedBackground = ({ className }: Props) => {
  return (
    <div
      className={cn(
        "h-full w-full absolute left-0 top-0 rounded-md overflow-hidden z-0 pointer-events-none",
        className
      )}
    >
      <div
        className={
          "bg-linear-to-b from-nb-gray-900/10 via-transparent to-transparent w-full h-full rounded-md"
        }
      ></div>
    </div>
  );
};
