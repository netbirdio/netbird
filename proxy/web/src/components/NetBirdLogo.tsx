import { cn } from "@/utils/helpers";
import netbirdFull from "@/assets/netbird-full.svg";
import netbirdMark from "@/assets/netbird.svg";

type Props = {
  size?: "small" | "default" | "large";
  mobile?: boolean;
};

const sizes = {
  small: {
    desktop: 14,
    mobile: 20,
  },
  default: {
    desktop: 22,
    mobile: 30,
  },
  large: {
    desktop: 24,
    mobile: 40,
  },
};

export const NetBirdLogo = ({ size = "default", mobile = true }: Props) => {
  return (
    <>
      <img
        src={netbirdFull}
        height={sizes[size].desktop}
        style={{ height: sizes[size].desktop }}
        alt="NetBird Logo"
        className={cn(mobile && "hidden md:block", "group-hover:opacity-80 transition-all")}
      />
      {mobile && (
        <img
          src={netbirdMark}
          width={sizes[size].mobile}
          style={{ width: sizes[size].mobile }}
          alt="NetBird Logo"
          className={cn(mobile && "md:hidden ml-4")}
        />
      )}
    </>
  );
};
