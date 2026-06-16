import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useMemo,
    useRef,
    useState,
    type ReactNode,
} from "react";
import { Events } from "@wailsio/runtime";
import { Connection, ProfileSwitcher, Profiles as ProfilesSvc } from "@bindings/services";
import type { Profile } from "@bindings/services/models.js";
import i18next from "@/lib/i18n";
import { errorDialog, formatErrorMessage } from "@/lib/errors";

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
    const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    const refresh = useCallback(async () => {
        if (retryRef.current) {
            clearTimeout(retryRef.current);
            retryRef.current = null;
        }
        try {
            const u = await ProfilesSvc.Username();
            const [active, list] = await Promise.all([
                ProfilesSvc.GetActive(),
                ProfilesSvc.List(u),
            ]);
            setUsername(u);
            setActiveProfile(active.profileName || "default");
            setProfiles(list);
            setLoaded(true);
        } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            if (msg.includes("code = Unavailable")) {
                retryRef.current = setTimeout(() => {
                    void refresh();
                }, 1000);
                return;
            }
            setLoaded(true);
            await errorDialog({
                Title: i18next.t("profile.error.loadTitle"),
                Message: formatErrorMessage(e),
            });
        }
    }, []);

    useEffect(() => {
        refresh().catch((err: unknown) => console.error("[ProfileContext] refresh failed", err));
        return () => {
            if (retryRef.current) clearTimeout(retryRef.current);
        };
    }, [refresh]);

    useEffect(() => {
        const off = Events.On(EVENT_PROFILE_CHANGED, () => {
            refresh().catch((err: unknown) =>
                console.error("[ProfileContext] refresh failed", err),
            );
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

    const value = useMemo<ProfileContextValue>(
        () => ({
            username,
            activeProfile,
            profiles,
            loaded,
            refresh,
            switchProfile,
            addProfile,
            removeProfile,
            logoutProfile,
        }),
        [
            username,
            activeProfile,
            profiles,
            loaded,
            refresh,
            switchProfile,
            addProfile,
            removeProfile,
            logoutProfile,
        ],
    );

    return <ProfileContext.Provider value={value}>{children}</ProfileContext.Provider>;
};
