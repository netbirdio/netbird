import { useLayoutEffect, useRef } from "react";
import { Window } from "@wailsio/runtime";
import i18next from "@/lib/i18n";

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
        const apply = () => {
            if (!ready) return;
            const h = Math.ceil(el.getBoundingClientRect().height);
            if (h <= 0) return;
            // Window.SetSize takes the frame size, so add the OS title-bar height or content clips.
            Window.Size()
                .then((frame) => {
                    const chrome = Math.max(0, frame.height - window.innerHeight);
                    return Window.SetSize(width, h + chrome);
                })
                .then(showOnce)
                .catch(() => {});
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
