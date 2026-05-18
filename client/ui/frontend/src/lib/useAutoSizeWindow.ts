import { useLayoutEffect, useRef } from "react";
import { Window } from "@wailsio/runtime";

// useAutoSizeWindow resizes the current Wails window so its height matches
// the measured height of the content element the returned ref is attached
// to. Width stays fixed (Wails has no "fit-content-width" notion and the
// dialog-style session windows want a stable horizontal footprint).
//
// On first measurement the hook also calls Window.Show()/Focus() — the
// Go-side opens the window with Hidden: true so the user never sees the
// initial placeholder size snap to the measured size. Subsequent
// measurements (content changes after mount) only adjust the size.
//
// Re-measures via ResizeObserver so adding/removing content (e.g. the
// SessionAboutToExpire title swapping at countdown zero) keeps the chrome
// tight to the content with no scrollbar.
export function useAutoSizeWindow<T extends HTMLElement>(width: number) {
    const ref = useRef<T | null>(null);
    useLayoutEffect(() => {
        const el = ref.current;
        if (!el) return;
        let shown = false;
        const apply = () => {
            const h = Math.ceil(el.getBoundingClientRect().height);
            if (h <= 0) return;
            void Window.SetSize(width, h)
                .then(() => {
                    if (shown) return;
                    shown = true;
                    void Window.Show().catch(() => {});
                    void Window.Focus().catch(() => {});
                })
                .catch(() => {});
        };
        apply();
        const ro = new ResizeObserver(apply);
        ro.observe(el);
        return () => ro.disconnect();
    }, [width]);
    return ref;
}
