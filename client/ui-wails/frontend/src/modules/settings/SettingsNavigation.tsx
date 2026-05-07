import { NavItem } from "@/components/NavItem.tsx";
import {
    InfoIcon,
    LifeBuoyIcon,
    NetworkIcon,
    SlidersHorizontalIcon,
    TerminalIcon,
} from "lucide-react";

export type SettingsSection =
    | "general"
    | "network"
    | "ssh"
    | "troubleshooting"
    | "about";

type Props = {
    active: SettingsSection;
    onChange: (section: SettingsSection) => void;
};

const ITEMS: {
    id: SettingsSection;
    icon: typeof SlidersHorizontalIcon;
    title: string;
}[] = [
    { id: "general", icon: SlidersHorizontalIcon, title: "General" },
    { id: "network", icon: NetworkIcon, title: "Network" },
    { id: "ssh", icon: TerminalIcon, title: "SSH" },
    { id: "troubleshooting", icon: LifeBuoyIcon, title: "Troubleshooting" },
    { id: "about", icon: InfoIcon, title: "About" },
];

export const SettingsNavigation = ({ active, onChange }: Props) => {
    return (
        <nav className={"w-full flex flex-col gap-1"}>
            {ITEMS.map(({ id, icon, title }) => (
                <NavItem
                    key={id}
                    icon={icon}
                    title={title}
                    iconSize={14}
                    iconBackground={false}
                    className={"py-2.5"}
                    active={active === id}
                    onClick={() => {
                        if (active !== id) onChange(id);
                    }}
                />
            ))}
        </nav>
    );
};
