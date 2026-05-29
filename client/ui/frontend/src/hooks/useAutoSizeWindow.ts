import { useLayoutEffect, useRef } from "react";
import { Window } from "@wailsio/runtime";
import i18next from "@/lib/i18n";

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
//
// Also re-measures on i18next `languageChanged`. The ResizeObserver in
// theory catches the same reflow when translated strings replace each
// other (DE/HU strings often wrap to more lines than EN), but in practice
// the observer can settle on a stale size before React's commit and the
// font's glyph metrics finish updating. An explicit double-rAF after the
// language flip guarantees the final layout is the one we measure.
export function useAutoSizeWindow<T extends HTMLElement>(width: number) {
    const ref = useRef<T | null>(null);
    useLayoutEffect(() => {
        const el = ref.current;
        if (!el) return;
        let shown = false;
        let raf1 = 0;
        let raf2 = 0;
        const apply = () => {
            const h = Math.ceil(el.getBoundingClientRect().height);
            if (h <= 0) return;
            // Wails Window.SetSize takes the *frame* size on every platform
            // (Windows: SetWindowPos, macOS: setFrame:, Linux: GTK frame).
            // The OS title bar lives inside the frame, so we have to add the
            // chrome height before calling SetSize, or the title bar eats
            // pixels from the bottom and the rendered content gets clipped.
            //
            // window.outerHeight / window.innerHeight are useless here:
            // WebView2 (and WKWebView) report the WebView's own outer == inner
            // because the WebView itself has no chrome — the OS title bar is
            // outside the WebView's window object entirely. The only way to
            // recover the chrome height is to compare the OS frame height
            // (Wails-side Window.Size()) against the WebView viewport
            // (window.innerHeight).
            void Window.Size()
                .then((frame) => {
                    const chrome = Math.max(0, frame.height - window.innerHeight);
                    return Window.SetSize(width, h + chrome);
                })
                .then(() => {
                    if (shown) return;
                    shown = true;
                    void Window.Show().catch(() => {});
                    void Window.Focus().catch(() => {});
                })
                .catch(() => {});
        };
        // Double rAF: first frame lands after React commits the new
        // translated strings, second frame lands after the browser has
        // recomputed layout, so apply() sees the final box.
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
    }, [width]);
    return ref;
}
