import { useEffect, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { PanelRightCloseIcon, PanelRightOpenIcon, SettingsIcon } from "lucide-react";
import { Window } from "@wailsio/runtime";
import { ProfileSelector } from "@/components/ProfileSelector.tsx";
import { IconButton } from "@/components/IconButton.tsx";
import { useAppearance } from "@/modules/appearance/AppearanceContext.tsx";
import { cn } from "@/lib/cn";

const WINDOW_SMALL_WIDTH = 380;
const WINDOW_BIG_WIDTH = 925;
const WINDOW_HEIGHT = 615;
const EXPANDED_THRESHOLD = 500;

export const Header = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const isSettingsPage = location.pathname.startsWith("/settings");
    const { showProfileSelector, showSettingsButton, expanded, setField } = useAppearance();
    const showSettings = showSettingsButton || isSettingsPage;
    const didInitialResize = useRef(false);

    useEffect(() => {
        if (didInitialResize.current) return;
        didInitialResize.current = true;
        const w = expanded ? WINDOW_BIG_WIDTH : WINDOW_SMALL_WIDTH;
        void Window.SetSize(w, WINDOW_HEIGHT).catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    useEffect(() => {
        const onResize = () => {
            const isWide = window.innerWidth >= EXPANDED_THRESHOLD;
            if (isWide !== expanded) setField("expanded", isWide);
        };
        window.addEventListener("resize", onResize);
        return () => window.removeEventListener("resize", onResize);
    }, [expanded, setField]);

    const togglePanel = () => {
        const next = !expanded;
        setField("expanded", next);
        const w = next ? WINDOW_BIG_WIDTH : WINDOW_SMALL_WIDTH;
        void Window.SetSize(w, WINDOW_HEIGHT).catch(() => {});
    };

    return (
        <div
            className={cn(
                "shrink-0 cursor-default wails-draggable flex items-center justify-end px-4 gap-3 bg-gradient-to-b from-nb-gray-800/15",
                "pt-4",
            )}
        >
            {showProfileSelector && (
                <div className={"ml-20"}>
                    <ProfileSelector email={"eduard@netbird.io"} />
                </div>
            )}

            <IconButton
                icon={expanded ? PanelRightOpenIcon : PanelRightCloseIcon}
                onClick={togglePanel}
            />
            {showSettings && (
                <IconButton
                    icon={SettingsIcon}
                    onClick={() => navigate(isSettingsPage ? "/" : "/settings")}
                    className={cn(
                        isSettingsPage &&
                            "bg-nb-gray-910 hover:bg-nb-gray-910 text-nb-gray-200 hover:text-nb-gray-200",
                    )}
                />
            )}
        </div>
    );
};
