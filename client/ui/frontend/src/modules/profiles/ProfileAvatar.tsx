import { type ButtonHTMLAttributes, forwardRef } from "react";
import {
    Briefcase,
    Building,
    Cloud,
    Construction,
    FlaskConical,
    Gamepad2,
    GraduationCap,
    House,
    Radio,
    Server,
    SquareCode,
    Terminal,
    UserCircle,
    UserPlus,
    Users,
    type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/cn";

// Scanned in order — put more-specific tokens first (e.g. "staging" before "stage").
const ICON_MAP: ReadonlyArray<[RegExp, LucideIcon]> = [
    [/(default|personal)/i, UserCircle],
    [/(work|business|office|company|corp|corporate)/i, Briefcase],
    [/(home|house|private)/i, House],
    [/(dev|development|developer|code|coding|engineering)/i, SquareCode],
    [/(local|localhost|loopback)/i, Terminal],
    [/(stage|staging|preprod|pre-prod)/i, Construction],
    [/(test|testing|qa)/i, FlaskConical],
    [/(prod|production)/i, Cloud],
    [/(live)/i, Radio],
    [/(selfhosted|self-hosted|on-prem|onprem)/i, Server],
    [/(school|university|edu|study|student)/i, GraduationCap],
    [/(client|customer)/i, Building],
    [/(family)/i, Users],
    [/(gaming|game)/i, Gamepad2],
    [/(guest)/i, UserPlus],
];

export const pickProfileIcon = (name: string | undefined): LucideIcon | null => {
    if (!name) return null;
    for (const [pattern, Icon] of ICON_MAP) {
        if (pattern.test(name)) return Icon;
    }
    return null;
};

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
    name?: string;
    size?: number;
};

export const ProfileAvatar = forwardRef<HTMLButtonElement, Props>(function ProfileAvatar(
    { name = "", size = 28, className, type = "button", ...props },
    ref,
) {
    const Icon = pickProfileIcon(name) ?? UserCircle;
    return (
        <button
            ref={ref}
            type={type}
            className={cn(
                "inline-grid place-items-center rounded-full bg-nb-gray-900 p-0 text-center",
                "cursor-default outline-none",
                "transition-colors duration-150 hover:bg-nb-gray-850",
                "data-[state=open]:bg-nb-gray-850",
                className,
            )}
            style={{ width: size, height: size }}
            {...props}
        >
            <Icon size={Math.round(size * 0.4)} className={"text-nb-gray-200"} />
        </button>
    );
});
