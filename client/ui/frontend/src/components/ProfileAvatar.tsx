import { ButtonHTMLAttributes, forwardRef } from "react";
import {
    Briefcase,
    Building2,
    Gamepad2,
    GraduationCap,
    House,
    Server,
    ServerCog,
    SquareCode,
    TestTube,
    UserCircle,
    UserPlus,
    Users,
    type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/cn";

const ICON_MAP: ReadonlyArray<[RegExp, LucideIcon]> = [
    [/\b(default|user|me|personal)\b/i, UserCircle],
    [/\b(work|business|office|company|corp|corporate)\b/i, Briefcase],
    [/\b(home|house|private)\b/i, House],
    [/\b(dev|development|developer|code|coding|engineering)\b/i, SquareCode],
    [/\b(local|localhost|loopback)\b/i, SquareCode],
    [/\b(test|testing|staging|qa|stage)\b/i, TestTube],
    [/\b(prod|production|live)\b/i, Server],
    [/\b(selfhosted|self-hosted|on-prem|onprem)\b/i, ServerCog],
    [/\b(school|university|edu|study|student)\b/i, GraduationCap],
    [/\b(client|customer)\b/i, Building2],
    [/\b(family)\b/i, Users],
    [/\b(gaming|game)\b/i, Gamepad2],
    [/\b(guest)\b/i, UserPlus],
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
