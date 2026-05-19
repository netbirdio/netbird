import { forwardRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Dialogs } from "@wailsio/runtime";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { Check, ChevronDown, PlusCircle, Settings2, UserCircle } from "lucide-react";
import { pickProfileIcon } from "@/components/ProfileAvatar";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/DropdownMenu";
import { NewProfileDialog } from "@/components/NewProfileDialog";
import { useProfile } from "@/modules/profile/ProfileContext";
import { cn } from "@/lib/cn";

type ProfileDropdownProps = {
    onManageProfiles?: () => void;
};

export const ProfileDropdown = ({ onManageProfiles }: ProfileDropdownProps) => {
    const { t } = useTranslation();
    const { activeProfile, profiles, addProfile, switchProfile } = useProfile();
    const [open, setOpen] = useState(false);
    const [newProfileOpen, setNewProfileOpen] = useState(false);
    const [busy, setBusy] = useState(false);

    const sortedProfiles = [...profiles].sort((a, b) =>
        a.name.localeCompare(b.name),
    );

    const guarded = async (title: string, fn: () => Promise<void>) => {
        if (busy) return;
        setBusy(true);
        try {
            await fn();
        } catch (e) {
            await Dialogs.Error({
                Title: title,
                Message: e instanceof Error ? e.message : String(e),
            });
        } finally {
            setBusy(false);
        }
    };

    const handleSelect = (name: string) => {
        setOpen(false);
        if (name === activeProfile) return;
        void guarded(t("profile.error.switchTitle"), () => switchProfile(name));
    };

    const handleAdd = () => {
        setOpen(false);
        setNewProfileOpen(true);
    };

    const handleManage = () => {
        setOpen(false);
        onManageProfiles?.();
    };

    const handleCreateProfile = async (name: string) => {
        try {
            await addProfile(name);
        } catch (e) {
            await Dialogs.Error({
                Title: t("profile.error.createTitle"),
                Message: e instanceof Error ? e.message : String(e),
            });
        }
    };

    const displayName = activeProfile || t("profile.selector.loading");

    return (
        <>
            <DropdownMenu modal={false} open={open} onOpenChange={setOpen}>
                <DropdownMenuTrigger asChild>
                    <ProfileTriggerButton name={displayName} />
                </DropdownMenuTrigger>
                <DropdownMenuContent className="w-64" align="start">
                    {sortedProfiles.length > 0 && (
                        <>
                            <ScrollArea.Root type="auto" className="overflow-hidden -mx-1">
                                <ScrollArea.Viewport className="max-h-56 px-1">
                                    {sortedProfiles.map((profile) => {
                                        const isActive = profile.name === activeProfile;
                                        const Icon = pickProfileIcon(profile.name) ?? UserCircle;
                                        return (
                                            <DropdownMenuItem
                                                key={profile.name}
                                                onClick={() => handleSelect(profile.name)}
                                            >
                                                <div className="flex items-center gap-3 w-full min-w-0">
                                                    <Icon size={14} className="shrink-0" />
                                                    <span className="capitalize truncate flex-1">
                                                        {profile.name}
                                                    </span>
                                                    {isActive && (
                                                        <Check
                                                            size={14}
                                                            className="shrink-0 text-nb-gray-200"
                                                        />
                                                    )}
                                                </div>
                                            </DropdownMenuItem>
                                        );
                                    })}
                                </ScrollArea.Viewport>
                                <ScrollArea.Scrollbar
                                    orientation="vertical"
                                    className={cn(
                                        "flex select-none touch-none transition-colors",
                                        "w-1.5 bg-transparent py-1",
                                    )}
                                >
                                    <ScrollArea.Thumb className="flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700 relative" />
                                </ScrollArea.Scrollbar>
                            </ScrollArea.Root>
                            <DropdownMenuSeparator />
                        </>
                    )}

                    <DropdownMenuItem onClick={handleAdd}>
                        <div className="flex items-center gap-3">
                            <PlusCircle size={14} />
                            {t("profile.dropdown.addProfile")}
                        </div>
                    </DropdownMenuItem>
                    <DropdownMenuItem
                        onClick={handleManage}
                        disabled={!onManageProfiles}
                    >
                        <div className="flex items-center gap-3">
                            <Settings2 size={14} />
                            {t("profile.dropdown.manageProfiles")}
                        </div>
                    </DropdownMenuItem>
                </DropdownMenuContent>
            </DropdownMenu>
            <NewProfileDialog
                open={newProfileOpen}
                onOpenChange={setNewProfileOpen}
                onCreate={handleCreateProfile}
            />
        </>
    );
};

type ProfileTriggerButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
    name: string;
};

const ProfileTriggerButton = forwardRef<HTMLButtonElement, ProfileTriggerButtonProps>(
    function ProfileTriggerButton({ name, className, ...props }, ref) {
        const Icon = pickProfileIcon(name) ?? UserCircle;
        return (
            <button
                ref={ref}
                type="button"
                className={cn(
                    "h-10 flex items-center gap-2 px-3 rounded-lg outline-none cursor-default",
                    "text-nb-gray-200 hover:bg-nb-gray-900",
                    "data-[state=open]:bg-nb-gray-900",
                    "transition-colors duration-150",
                    className,
                )}
                {...props}
            >
                <Icon size={16} className={"text-nb-gray-200 shrink-0"} />
                <span className={"text-sm font-medium capitalize truncate max-w-[140px]"}>
                    {name}
                </span>
                <ChevronDown size={14} className={"text-nb-gray-200 shrink-0"} />
            </button>
        );
    },
);
