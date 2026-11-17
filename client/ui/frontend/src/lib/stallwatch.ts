// Detects webview suspension (macOS App Nap / hidden-window timer throttling).
// While the webview is suspended no JS runs at all, so detection happens on
// resume: a 1s interval measures wall-clock drift and reports how long timers
// were frozen. Silent unless a stall actually occurred; a stalled webview is
// what delays promise continuations such as the WaitSSOLogin → Up handoff.

const INTERVAL_MS = 1000;
const STALL_THRESHOLD_MS = 5000;
const REPORT_COOLDOWN_MS = 60_000;

let started = false;

export function initStallWatch() {
    if (started) return;
    started = true;

    let last = Date.now();
    let lastReport = 0;
    setInterval(() => {
        const now = Date.now();
        const stall = now - last - INTERVAL_MS;
        last = now;
        if (stall < STALL_THRESHOLD_MS) return;
        if (now - lastReport < REPORT_COOLDOWN_MS) return;
        lastReport = now;
        console.warn(
            `webview timers were suspended for ${(stall / 1000).toFixed(1)}s ` +
                `(App Nap / hidden-window throttling); pending UI work ran late`,
        );
    }, INTERVAL_MS);
}
