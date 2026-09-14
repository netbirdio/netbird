import { useLayoutEffect, useRef } from "react";
import { Window } from "@wailsio/runtime";
import i18next from "@/lib/i18n";
import { isLinux } from "@/lib/platform";

// Sizes the current Wails window to the measured content height (keeping `width`),
// then shows it. Re-applies on content resize and language change.
export function useAutoSizeWindow<T extends HTMLElement>(width: number, ready: boolean = true) {
    const ref = useRef<T | null>(null);
    useLayoutEffect(() => {
        const el = ref.current;
        if (!el) return;
        let shown = false;
        let raf1 = 0;
        let raf2 = 0;
        const showOnce = () => {
            if (shown) return;
            shown = true;
            Window.Show().catch(() => {});
            Window.Focus().catch(() => {});
        };
        const apply = async () => {
            if (!ready) return;
            const h = Math.ceil(el.getBoundingClientRect().height);
            if (h <= 0) return;
            try {
                // Window.SetSize takes the frame size, so add the OS title-bar height or content clips.
                const frame = await Window.Size();
                const targetH = h + Math.max(0, frame.height - window.innerHeight);
                // Linux: SetSize no-ops on a mapped non-resizable window (X11), so pin via min/max instead.
                if (isLinux()) {
                    await Window.SetMinSize(width, targetH);
                    await Window.SetMaxSize(width, targetH);
                }
                await Window.SetSize(width, targetH);
                showOnce();
            } catch {
                // window gone / not ready — ignore
            }
        };
        const scheduleApply = () => {
            cancelAnimationFrame(raf1);
            cancelAnimationFrame(raf2);
            raf1 = requestAnimationFrame(() => {
                raf2 = requestAnimationFrame(apply);
            });
        };
        apply();
        const ro = new ResizeObserver(apply);
        ro.observe(el);
        i18next.on("languageChanged", scheduleApply);
        return () => {
            ro.disconnect();
            cancelAnimationFrame(raf1);
            cancelAnimationFrame(raf2);
            i18next.off("languageChanged", scheduleApply);
        };
    }, [width, ready]);
    return ref;
}
