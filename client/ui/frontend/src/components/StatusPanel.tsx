import type { ReactNode } from "react";
import { Check, Loader2, XCircle } from "lucide-react";
import { cn } from "@/lib/cn";

type Variant = "loading" | "success" | "error";

type Props = {
    variant: Variant;
    title: ReactNode;
    description?: ReactNode;
    children?: ReactNode;
    actions?: ReactNode;
};

const VARIANTS: Record<Variant, { icon: ReactNode; className: string }> = {
    loading: {
        icon: <Loader2 className={"animate-spin text-nb-gray-950"} size={16} />,
        className: "bg-nb-gray-100",
    },
    success: {
        icon: <Check className={"text-white"} size={18} />,
        className: "bg-green-500",
    },
    error: {
        icon: <XCircle className={"text-white"} size={18} />,
        className: "bg-red-500",
    },
};

export function StatusPanel({ variant, title, description, children, actions }: Props) {
    const { icon, className } = VARIANTS[variant];
    return (
        <div className={"absolute inset-0 flex flex-col items-center justify-center gap-5 px-8"}>
            <div className={cn("h-9 w-9 rounded-md flex items-center justify-center", className)}>
                {icon}
            </div>

            <div className={"flex flex-col items-center gap-0.5 max-w-md text-center"}>
                <p className={"text-base font-medium text-nb-gray-50"}>{title}</p>
                {description && <p className={"text-sm text-nb-gray-300"}>{description}</p>}
            </div>

            {children && <div className={"w-full max-w-md flex flex-col gap-3"}>{children}</div>}

            {actions && <div className={"flex items-center gap-2"}>{actions}</div>}
        </div>
    );
}
