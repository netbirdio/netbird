import { Events } from "@wailsio/runtime";
import { Connection, WindowManager } from "@bindings/services";
import i18next from "@/lib/i18n";
import { errorDialog, formatErrorMessage } from "@/lib/errors.ts";

export const EVENT_BROWSER_LOGIN_CANCEL = "browser-login:cancel";
export const EVENT_TRIGGER_LOGIN = "trigger-login";

let connectionInFlight = false;

export async function startConnection(onSettled?: () => void, signal?: AbortSignal): Promise<void> {
    if (connectionInFlight) {
        onSettled?.();
        return;
    }
    if (signal?.aborted) {
        onSettled?.();
        return;
    }
    connectionInFlight = true;

    let cancelled = false;
    let offCancel: (() => void) | undefined;
    let offSignal: (() => void) | undefined;
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

        if (signal?.aborted) cancelled = true;

        if (!cancelled && result.needsSsoLogin) {
            const uri = result.verificationUriComplete || result.verificationUri;
            if (uri) {
                try {
                    await WindowManager.OpenBrowserLogin(uri);
                } catch (e) {
                    console.error(e);
                }
            }

            const cancelPromise = new Promise<void>((resolve) => {
                offCancel = Events.On(EVENT_BROWSER_LOGIN_CANCEL, () => {
                    cancelled = true;
                    resolve();
                });
                if (signal) {
                    const onAbort = () => {
                        cancelled = true;
                        resolve();
                    };
                    if (signal.aborted) {
                        onAbort();
                    } else {
                        signal.addEventListener("abort", onAbort);
                        offSignal = () => signal.removeEventListener("abort", onAbort);
                    }
                }
            });

            const waitPromise = Connection.WaitSSOLogin({
                userCode: result.userCode,
                hostname: "",
            });

            try {
                await Promise.race([waitPromise, cancelPromise]);
            } finally {
                WindowManager.CloseBrowserLogin().catch(console.error);
            }

            if (cancelled) {
                waitPromise.cancel?.();
                waitPromise.catch(() => {});
            }
        }

        if (!cancelled && signal?.aborted) cancelled = true;

        if (!cancelled) {
            await Connection.Up({ profileName: "", username: "" });
        }
    } catch (e) {
        WindowManager.CloseBrowserLogin().catch(console.error);
        if (!cancelled) connectError = e;
    } finally {
        offCancel?.();
        offSignal?.();
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

    if (cancelled && signal) {
        throw new DOMException("aborted", "AbortError");
    }
}
