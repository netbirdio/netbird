import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useState,
    type ReactNode,
} from "react";
import { Profiles as ProfilesSvc } from "@bindings/services";

type ProfileContextValue = {
    username: string;
    activeProfile: string;
    loaded: boolean;
    error: string | null;
    refresh: () => Promise<void>;
    switchProfile: (name: string) => Promise<void>;
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
    const [loaded, setLoaded] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const refresh = useCallback(async () => {
        try {
            const u = await ProfilesSvc.Username();
            const active = await ProfilesSvc.GetActive();
            setUsername(u);
            setActiveProfile(active.profileName || "default");
            setError(null);
        } catch (e) {
            setError(String(e));
        } finally {
            setLoaded(true);
        }
    }, []);

    useEffect(() => {
        refresh();
    }, [refresh]);

    const switchProfile = useCallback(
        async (name: string) => {
            await ProfilesSvc.Switch({ profileName: name, username });
            setActiveProfile(name);
        },
        [username],
    );

    return (
        <ProfileContext.Provider
            value={{
                username,
                activeProfile,
                loaded,
                error,
                refresh,
                switchProfile,
            }}
        >
            {children}
        </ProfileContext.Provider>
    );
};
