import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useState,
    type ReactNode,
} from "react";
import { Dialogs, Events } from "@wailsio/runtime";
import {
    Connection,
    ProfileSwitcher,
    Profiles as ProfilesSvc,
} from "@bindings/services";
import type { Profile } from "@bindings/services/models.js";
import i18next from "@/lib/i18n";

const EVENT_PROFILE_CHANGED = "netbird:profile:changed";

type ProfileContextValue = {
    username: string;
    activeProfile: string;
    profiles: Profile[];
    loaded: boolean;
    refresh: () => Promise<void>;
    switchProfile: (name: string) => Promise<void>;
    addProfile: (name: string) => Promise<void>;
    removeProfile: (name: string) => Promise<void>;
    logoutProfile: (name: string) => Promise<void>;
};

const ProfileContext = createContext<ProfileContextValue | null>(null);

export const useProfile = () => {
    const ctx = useContext(ProfileContext);
    if (!ctx) {
        throw new Error("useProfile must be used inside ProfileProvider");
    }
    return ctx;
};

export const ProfileProvider = ({ children }: { children: ReactNode }) => {
    const [username, setUsername] = useState("");
    const [activeProfile, setActiveProfile] = useState("");
    const [profiles, setProfiles] = useState<Profile[]>([]);
    const [loaded, setLoaded] = useState(false);

    const refresh = useCallback(async () => {
        try {
            const u = await ProfilesSvc.Username();
            const [active, list] = await Promise.all([
                ProfilesSvc.GetActive(),
                ProfilesSvc.List(u),
            ]);
            setUsername(u);
            setActiveProfile(active.profileName || "default");
            setProfiles(list);
        } catch (e) {
            await Dialogs.Error({
                Title: i18next.t("profile.error.loadTitle"),
                Message: e instanceof Error ? e.message : String(e),
            });
        } finally {
            setLoaded(true);
        }
    }, []);

    useEffect(() => {
        refresh();
        // The tray and other windows drive switches through the same
        // ProfileSwitcher.SwitchActive RPC, which emits this event on success.
        // Without the subscription, a tray-initiated switch leaves this
        // window painting the old activeProfile until the next mount.
        const off = Events.On(EVENT_PROFILE_CHANGED, () => {
            void refresh();
        });
        return () => {
            off();
        };
    }, [refresh]);

    const switchProfile = useCallback(
        async (name: string) => {
            await ProfileSwitcher.SwitchActive({ profileName: name, username });
            await refresh();
        },
        [username, refresh],
    );

    const addProfile = useCallback(
        async (name: string) => {
            await ProfilesSvc.Add({ profileName: name, username });
            await refresh();
        },
        [username, refresh],
    );

    const removeProfile = useCallback(
        async (name: string) => {
            await ProfilesSvc.Remove({ profileName: name, username });
            await refresh();
        },
        [username, refresh],
    );

    const logoutProfile = useCallback(
        async (name: string) => {
            await Connection.Logout({ profileName: name, username });
            await refresh();
        },
        [username, refresh],
    );

    return (
        <ProfileContext.Provider
            value={{
                username,
                activeProfile,
                profiles,
                loaded,
                refresh,
                switchProfile,
                addProfile,
                removeProfile,
                logoutProfile,
            }}
        >
            {children}
        </ProfileContext.Provider>
    );
};
