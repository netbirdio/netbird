import { ButtonHTMLAttributes, forwardRef } from "react";
import { generateColorFromString } from "@/lib/color";
import { cn } from "@/lib/cn";

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
    name?: string;
    size?: number;
};

export const Avatar = forwardRef<HTMLButtonElement, Props>(function Avatar(
    { name = "", size = 28, className, type = "button", ...props },
    ref,
) {
    const initial = (name.trim().charAt(0) || "?").toUpperCase();
    const color = generateColorFromString(name);

    return (
        <button
            ref={ref}
            type={type}
            className={cn(
                "inline-grid place-items-center rounded-full bg-nb-gray-850 p-0 text-center",
                "text-[0.9rem] font-semibold cursor-default outline-none",
                "transition-colors duration-150 hover:bg-nb-gray-850",
                "data-[state=open]:bg-nb-gray-850",
                className,
            )}
            style={{
                width: size,
                height: size,
                color,
                lineHeight: 0,
                letterSpacing: 0,
            }}
            {...props}
        >
            {initial}
        </button>
    );
});
