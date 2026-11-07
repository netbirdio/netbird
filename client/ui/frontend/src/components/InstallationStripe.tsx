import { useInstallation } from "@/hooks/useInstallation";

// A stripe in the installation colour across the top of the window, so two
// NetBird windows can be told apart. It overlays the content instead of taking
// layout space, so pages sized to the window keep their height, and stays above
// full-window overlays such as the daemon-unavailable screen. The default
// installation shows none.
export const InstallationStripe = () => {
    const installation = useInstallation();
    if (!installation?.color) return null;
    return (
        <div
            aria-hidden={"true"}
            className={"pointer-events-none fixed inset-x-0 top-0 z-[1000] h-1"}
            style={{ backgroundColor: installation.color }}
        />
    );
};
