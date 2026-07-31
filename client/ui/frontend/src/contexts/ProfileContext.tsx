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
    // activeProfile is the display NAME of the active profile (for rendering
    // and the "default" check). activeProfileId is its stable on-disk ID, used
    // as the handle for daemon requests and for active-profile comparisons,
    // since display names can collide.
    activeProfile: string;
    activeProfileId: string;
    profiles: Profile[];
    loaded: boolean;
    refresh: () => Promise<void>;
    switchProfile: (id: string) => Promise<void>;
    switchProfileNoConnect: (id: string) => Promise<void>;
    addProfile: (name: string) => Promise<string>;
    removeProfile: (id: string) => Promise<void>;
    renameProfile: (id: string, newName: string) => Promise<void>;
    logoutProfile: (id: string) => Promise<void>;
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
    const [activeProfileId, setActiveProfileId] = useState("");
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
            setActiveProfileId(active.id || "default");
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

    // id is a handle: the daemon resolves an exact ID, ID prefix, or unique
    // display name. The UI passes the profile's ID for precision.
    const switchProfile = useCallback(
        async (id: string) => {
            await ProfileSwitcher.SwitchActive({ profileName: id, username });
            await refresh();
        },
        [username, refresh],
    );

    // Manage-profiles variant: switches without connecting, so the user can
    // still adjust the management URL before bringing the connection up.
    const switchProfileNoConnect = useCallback(
        async (id: string) => {
            await ProfileSwitcher.SwitchActiveNoConnect({ profileName: id, username });
            await refresh();
        },
        [username, refresh],
    );

    // addProfile creates a profile by display name and returns the
    // daemon-generated ID, so the caller can immediately address it by ID.
    const addProfile = useCallback(
        async (name: string) => {
            const id = await ProfilesSvc.Add({ profileName: name, username });
            await refresh();
            return id;
        },
        [username, refresh],
    );

    const removeProfile = useCallback(
        async (id: string) => {
            await ProfilesSvc.Remove({ profileName: id, username });
            await refresh();
        },
        [username, refresh],
    );

    // The daemon resolves the handle (exact ID, ID prefix, or unique display
    // name) — passing the ID is precise and avoids collisions on rename.
    const renameProfile = useCallback(
        async (id: string, newName: string) => {
            await ProfilesSvc.Rename({ handle: id, newName, username });
            await refresh();
        },
        [username, refresh],
    );

    const logoutProfile = useCallback(
        async (id: string) => {
            await Connection.Logout({ profileName: id, username });
            await refresh();
        },
        [username, refresh],
    );

    const value = useMemo<ProfileContextValue>(
        () => ({
            username,
            activeProfile,
            activeProfileId,
            profiles,
            loaded,
            refresh,
            switchProfile,
            switchProfileNoConnect,
            addProfile,
            removeProfile,
            renameProfile,
            logoutProfile,
        }),
        [
            username,
            activeProfile,
            activeProfileId,
            profiles,
            loaded,
            refresh,
            switchProfile,
            switchProfileNoConnect,
            addProfile,
            removeProfile,
            renameProfile,
            logoutProfile,
        ],
    );

    return <ProfileContext.Provider value={value}>{children}</ProfileContext.Provider>;
};
