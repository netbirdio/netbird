import { Events } from "@wailsio/runtime";
import { Connection, WindowManager } from "@bindings/services";
import i18next from "@/lib/i18n";
import { errorDialog, formatErrorMessage } from "@/lib/errors.ts";

export const EVENT_BROWSER_LOGIN_CANCEL = "browser-login:cancel";
export const EVENT_TRIGGER_LOGIN = "trigger-login";

let connectionInFlight = false;

type SsoState = {
    cancelled: boolean;
    offCancel?: () => void;
    offSignal?: () => void;
};

async function openBrowserLoginUri(uri: string): Promise<void> {
    try {
        await WindowManager.OpenBrowserLogin(uri);
    } catch (e) {
        console.error(e);
    }
}

function buildSsoCancelPromise(state: SsoState, signal?: AbortSignal): Promise<void> {
    return new Promise<void>((resolve) => {
        state.offCancel = Events.On(EVENT_BROWSER_LOGIN_CANCEL, () => {
            state.cancelled = true;
            resolve();
        });
        if (!signal) return;
        const onAbort = () => {
            state.cancelled = true;
            resolve();
        };
        if (signal.aborted) {
            onAbort();
            return;
        }
        signal.addEventListener("abort", onAbort);
        state.offSignal = () => signal.removeEventListener("abort", onAbort);
    });
}

async function runSsoLogin(
    result: { verificationUri: string; verificationUriComplete: string; userCode: string },
    state: SsoState,
    signal?: AbortSignal,
): Promise<void> {
    const uri = result.verificationUriComplete || result.verificationUri;
    if (uri) await openBrowserLoginUri(uri);

    const cancelPromise = buildSsoCancelPromise(state, signal);
    // Combine wait + up in Go so the connection comes up the moment SSO
    // completes. During SSO the tray window is hidden and the webview is
    // suspended, so a frontend-driven Up (a promise continuation) would not
    // fire until the user woke the window (e.g. hovering the tray icon).
    const waitPromise = Connection.WaitSSOLoginAndUp(
        { userCode: result.userCode, hostname: "" },
        { profileName: "", username: "" },
    );

    try {
        await Promise.race([waitPromise, cancelPromise]);
    } finally {
        WindowManager.CloseBrowserLogin().catch(console.error);
    }

    if (state.cancelled) {
        waitPromise.cancel?.();
        waitPromise.catch(() => {});
    }
}

export async function startConnection(onSettled?: () => void, signal?: AbortSignal): Promise<void> {
    if (connectionInFlight || signal?.aborted) {
        onSettled?.();
        return;
    }
    connectionInFlight = true;

    const state: SsoState = { cancelled: false };
    let connectError: unknown;

    try {
        const result = await Connection.Login({
            profileName: "",
            username: "",
            managementUrl: "",
            setupKey: "",
            preSharedKey: "",
            hostname: "",
            hint: "",
        });

        if (signal?.aborted) state.cancelled = true;

        if (!state.cancelled && result.needsSsoLogin) {
            // runSsoLogin brings the connection up in Go once SSO completes.
            await runSsoLogin(result, state, signal);
        } else {
            if (!state.cancelled && signal?.aborted) state.cancelled = true;
            if (!state.cancelled) {
                await Connection.Up({ profileName: "", username: "" });
            }
        }
    } catch (e) {
        WindowManager.CloseBrowserLogin().catch(console.error);
        if (!state.cancelled) connectError = e;
    } finally {
        state.offCancel?.();
        state.offSignal?.();
        connectionInFlight = false;
        onSettled?.();
    }

    if (connectError !== undefined) {
        await errorDialog({
            Title: i18next.t("connect.error.loginTitle"),
            Message: formatErrorMessage(connectError),
        });
        return;
    }

    if (state.cancelled && signal) {
        throw new DOMException("aborted", "AbortError");
    }
}
