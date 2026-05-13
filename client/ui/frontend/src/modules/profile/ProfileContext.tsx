import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useState,
    type ReactNode,
} from "react";
import { Dialogs } from "@wailsio/runtime";
import { Connection, Peers, Profiles as ProfilesSvc } from "@bindings/services";
import type { Profile } from "@bindings/services/models.js";

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
                Title: "Load Profiles Failed",
                Message: e instanceof Error ? e.message : String(e),
            });
        } finally {
            setLoaded(true);
        }
    }, []);

    useEffect(() => {
        refresh();
    }, [refresh]);

    const switchProfile = useCallback(
        async (name: string) => {
            // Mirror tray.go switchProfile: only reconnect when the daemon was
            // actively online. Calling Up on an Idle/NeedsLogin daemon makes
            // the daemon wait 50s on its internal waitForUp and return
            // DeadlineExceeded.
            let wasActive = false;
            try {
                const prev = await Peers.Get();
                const s = (prev?.status ?? "").toLowerCase();
                wasActive = s === "connected" || s === "connecting";
            } catch {
                wasActive = false;
            }

            await ProfilesSvc.Switch({ profileName: name, username });

            if (wasActive) {
                await Connection.Down();
                await Connection.Up({ profileName: name, username });
            }

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
