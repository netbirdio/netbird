// Shared error formatter for native dialog bodies.
//
// The Go service layer (client/ui/services/connection.go classifyDaemonError)
// wraps daemon errors in a ClientError struct exposed to the TS side as
// {code, short, long}. Short is already localised (Go reads the current
// preferences.Store language and resolves "error.<code>" via i18n.Bundle).
// Long always carries the unwrapped raw daemon message so the operator can
// see the JWT / mgm stack when the short text is too generic.
//
// Wails wraps Go-returned errors as Error({message, cause, kind}) where
// .message holds the JSON-stringified payload and the structured object
// lives on .cause — Object.keys(err) is empty in that case. We therefore
// probe .cause first, then fall back to parsing .message as JSON, then
// to plain .message text for callers that still hand us a raw Error.
const extractClientError = (e: unknown): { short?: string; long?: string } | null => {
    if (!e || typeof e !== "object") return null;
    const withCause = e as { cause?: unknown; message?: unknown };
    if (withCause.cause && typeof withCause.cause === "object") {
        return withCause.cause as { short?: string; long?: string };
    }
    if (typeof withCause.message === "string") {
        const m = withCause.message.trim();
        if (m.startsWith("{") && m.endsWith("}")) {
            try {
                const parsed = JSON.parse(m);
                if (parsed && typeof parsed === "object") {
                    if ("cause" in parsed && parsed.cause && typeof parsed.cause === "object") {
                        return parsed.cause as { short?: string; long?: string };
                    }
                    return parsed as { short?: string; long?: string };
                }
            } catch {
                // not JSON — fall through to plain-message handling
            }
        }
    }
    return null;
};

export const formatErrorMessage = (e: unknown): string => {
    const ce = extractClientError(e);
    if (ce) {
        const short = typeof ce.short === "string" ? ce.short : "";
        const long = typeof ce.long === "string" ? ce.long : "";
        if (short && long && long !== short) {
            return `${short}\n\nDetails: ${long}`;
        }
        if (short) return short;
    }
    if (e instanceof Error) return e.message;
    return String(e);
};
