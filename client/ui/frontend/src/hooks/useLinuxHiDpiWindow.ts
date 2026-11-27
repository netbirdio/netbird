import { useEffect } from "react";
import { Window } from "@wailsio/runtime";
import { isLinux } from "@/lib/platform";

// Window resizes that must not interleave share this queue: the mount-time
// HiDPI scaling and the view-mode switch both resize the main window, and a
// switch during startup could otherwise be overwritten by the mount resize
// landing after it.
let resizeChain: Promise<void> = Promise.resolve();

export function enqueueWindowResize(op: () => Promise<unknown>): Promise<void> {
    resizeChain = resizeChain.then(async () => {
        try {
            await op();
        } catch (err) {
            // A failed resize must not break the chain for the ones behind it.
            console.warn("[useLinuxHiDpiWindow] queued window resize failed", err);
        }
    });
    return resizeChain;
}

type LinuxHiDpiWindowOptions = {
    // Log tag naming the caller in warnings.
    tag: string;
    // GTK-unscaled default widths the window is created with; scaling is
    // skipped when the window manager restored a different size.
    defaultWidths: readonly number[];
    // GTK-unscaled minimum, scaled with the same ratio so resizing cannot
    // squeeze the layout below its CSS-pixel budget.
    minWidth: number;
    minHeight: number;
};

// On Linux, WebKitGTK applies its own DPR from Xft.dpi while GTK's window
// size stays in unscaled pixels, shrinking the CSS viewport. Scale the window
// and its minimum on mount so the CSS viewport matches the intended layout.
export function useLinuxHiDpiWindow({
    tag,
    defaultWidths,
    minWidth,
    minHeight,
}: LinuxHiDpiWindowOptions) {
    useEffect(() => {
        if (!isLinux()) return;
        const dpr = window.devicePixelRatio;
        if (dpr <= 1) return;
        enqueueWindowResize(() =>
            Window.Size()
                .then((frame) => {
                    // Scale by the frame-to-viewport ratio rather than the raw
                    // devicePixelRatio: when GTK itself already scales the window
                    // (GDK_SCALE), the viewport matches the frame, the ratio is 1,
                    // and the window is not enlarged twice.
                    const ratio = frame.width / window.innerWidth;
                    const shrink = Number.isFinite(ratio) && ratio > 1 ? ratio : 1;
                    const scale = (v: number) => Math.round(v * shrink);
                    // The minimum is applied after the size so it cannot clamp
                    // the still-unscaled window past the default-width check.
                    const setMin = () =>
                        Window.SetMinSize(scale(minWidth), scale(minHeight)).catch((err: unknown) =>
                            console.warn(`[${tag}] set minimum size failed`, err),
                        );
                    if (!defaultWidths.includes(frame.width) || shrink === 1) return setMin();
                    return Window.SetSize(scale(frame.width), scale(frame.height))
                        .catch((err: unknown) => console.warn(`[${tag}] HiDPI resize failed`, err))
                        .then(setMin);
                })
                .catch((err: unknown) => console.warn(`[${tag}] read window size failed`, err)),
        );
    }, [tag, defaultWidths, minWidth, minHeight]);
}
