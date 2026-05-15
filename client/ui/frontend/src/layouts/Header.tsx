import { useEffect, useRef } from "react";
import { PanelRightCloseIcon, PanelRightOpenIcon, SettingsIcon } from "lucide-react";
import { Window } from "@wailsio/runtime";
import { WindowManager } from "@bindings/services";
import { ProfileSelector } from "@/components/ProfileSelector.tsx";
import { IconButton } from "@/components/IconButton.tsx";
import { cn } from "@/lib/cn";

const WINDOW_SMALL_WIDTH = 380;
const WINDOW_BIG_WIDTH = 925;
const WINDOW_HEIGHT = 615;
const EXPANDED_THRESHOLD = 500;

type HeaderProps = {
    expanded: boolean;
    setExpanded: (next: boolean) => void;
};

export const Header = ({ expanded, setExpanded }: HeaderProps) => {
    const didInitialResize = useRef(false);

    useEffect(() => {
        if (didInitialResize.current) return;
        didInitialResize.current = true;
        const w = expanded ? WINDOW_BIG_WIDTH : WINDOW_SMALL_WIDTH;
        void Window.SetSize(w, WINDOW_HEIGHT).catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    useEffect(() => {
        if (!didInitialResize.current) return;
        const w = expanded ? WINDOW_BIG_WIDTH : WINDOW_SMALL_WIDTH;
        void Window.SetSize(w, WINDOW_HEIGHT).catch(() => {});
    }, [expanded]);

    useEffect(() => {
        const onResize = () => {
            const isWide = window.innerWidth >= EXPANDED_THRESHOLD;
            if (isWide !== expanded) setExpanded(isWide);
        };
        window.addEventListener("resize", onResize);
        return () => window.removeEventListener("resize", onResize);
    }, [expanded, setExpanded]);

    const togglePanel = () => {
        const next = !expanded;
        setExpanded(next);
        const w = next ? WINDOW_BIG_WIDTH : WINDOW_SMALL_WIDTH;
        void Window.SetSize(w, WINDOW_HEIGHT).catch(() => {});
    };

    const openSettings = () => {
        void WindowManager.OpenSettings().catch(() => {});
    };

    return (
        <div
            className={cn(
                "shrink-0 cursor-default wails-draggable flex items-center justify-end px-4 gap-3 bg-gradient-to-b from-nb-gray-800/15",
                "pt-4",
            )}
        >
            <div className={"ml-20"}>
                <ProfileSelector />
            </div>

            <IconButton
                icon={expanded ? PanelRightOpenIcon : PanelRightCloseIcon}
                onClick={togglePanel}
            />
            <IconButton icon={SettingsIcon} onClick={openSettings} />
        </div>
    );
};
