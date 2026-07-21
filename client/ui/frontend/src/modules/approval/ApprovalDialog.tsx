import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { MonitorIcon } from "lucide-react";
import { Button } from "@/components/buttons/Button";
import { ConfirmDialog } from "@/components/dialog/ConfirmDialog";
import { DialogActions } from "@/components/dialog/DialogActions";
import { DialogHeading } from "@/components/dialog/DialogHeading";
import { SquareIcon } from "@/components/SquareIcon";
import { Approval, WindowManager } from "@bindings/services";
import { useAutoSizeWindow } from "@/hooks/useAutoSizeWindow";

const WINDOW_WIDTH = 360;
// Fallback window so a missing/unparseable expires_at can't leave the prompt open forever.
const FALLBACK_SECONDS = 13;

// shortFingerprint groups a hex key as XXXX-XXXX-XXXX-XXXX (16 chars). Mirrors the
// daemon's approval.ShortKeyFingerprint so the value matches an out-of-band reference.
function shortFingerprint(hexKey: string): string {
    if (hexKey.length < 8) return "";
    const src = hexKey.slice(0, 16);
    return src.match(/.{1,4}/g)?.join("-") ?? src;
}

type Row = { label: string; value: string; mono?: boolean };

export default function ApprovalDialog() {
    const { t } = useTranslation();
    const contentRef = useAutoSizeWindow<HTMLDivElement>(WINDOW_WIDTH);
    const [params] = useSearchParams();
    const [busy, setBusy] = useState(false);

    const requestID = params.get("request_id") ?? "";
    const kind = params.get("kind") ?? "";
    const initiator = params.get("initiator") ?? "";
    const peerName = params.get("peer_name") ?? "";
    const sourceIP = params.get("source_ip") ?? "";
    const username = params.get("username") ?? "";
    const peerPubKey = params.get("peer_pubkey") ?? "";
    const expiresAt = params.get("expires_at") ?? "";

    const deadline = useMemo(() => {
        const parsed = Date.parse(expiresAt);
        return Number.isFinite(parsed) ? parsed : Date.now() + FALLBACK_SECONDS * 1000;
    }, [expiresAt]);

    const title = useMemo(() => {
        switch (kind) {
            case "vnc":
                return t("approval.title.vnc");
            case "ssh":
                return t("approval.title.ssh");
            default:
                return t("approval.title.default");
        }
    }, [kind, t]);

    const rows = useMemo<Row[]>(() => {
        const out: Row[] = [];
        // The display name is dashboard-supplied and not cryptographically
        // asserted; the key fingerprint below IS, so show both.
        if (initiator) out.push({ label: t("approval.field.user"), value: initiator });
        const fp = shortFingerprint(peerPubKey);
        if (fp) out.push({ label: t("approval.field.keyFingerprint"), value: fp, mono: true });
        if (peerName) out.push({ label: t("approval.field.peer"), value: peerName });
        if (sourceIP && sourceIP !== peerName)
            out.push({ label: t("approval.field.sourceIp"), value: sourceIP, mono: true });
        if (username) out.push({ label: t("approval.field.osUser"), value: username });
        return out;
    }, [initiator, peerPubKey, peerName, sourceIP, username, t]);

    const respond = useCallback(
        async (accept: boolean, viewOnly: boolean) => {
            if (busy) return;
            setBusy(true);
            try {
                if (requestID) {
                    await Approval.Respond(requestID, accept, viewOnly);
                }
            } catch (e) {
                console.error("respond approval failed", e);
            } finally {
                WindowManager.CloseApproval().catch(console.error);
            }
        },
        [busy, requestID],
    );

    const secondsLeft = () => Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    const [remaining, setRemaining] = useState(secondsLeft);
    const closedRef = useRef(false);
    useEffect(() => {
        const id = globalThis.setInterval(() => {
            const left = secondsLeft();
            setRemaining(left);
            // On the deadline the daemon auto-denies; just close the prompt.
            if (left <= 0 && !closedRef.current) {
                closedRef.current = true;
                WindowManager.CloseApproval().catch(console.error);
            }
        }, 1000);
        return () => globalThis.clearInterval(id);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [deadline]);

    const showViewOnly = kind === "vnc";

    return (
        <ConfirmDialog ref={contentRef} aria-labelledby={"nb-approval-title"}>
            <SquareIcon icon={MonitorIcon} />

            <DialogHeading id={"nb-approval-title"}>{title}</DialogHeading>

            {rows.length > 0 && (
                <dl className={"w-full space-y-1 text-left text-sm"}>
                    {rows.map((row) => (
                        <div key={row.label} className={"flex justify-between gap-4"}>
                            <dt className={"shrink-0 text-nb-gray-400"}>{row.label}</dt>
                            <dd
                                className={`min-w-0 truncate text-nb-gray-100 ${
                                    row.mono ? "font-mono" : ""
                                }`}
                                title={row.value}
                            >
                                {row.value}
                            </dd>
                        </div>
                    ))}
                </dl>
            )}

            <div className={"text-sm tabular-nums text-nb-gray-400"} aria-live={"polite"}>
                {t("approval.countdown", { seconds: remaining })}
            </div>

            <DialogActions>
                <Button
                    autoFocus
                    variant={"primary"}
                    size={"md"}
                    className={"w-full"}
                    onClick={() => respond(true, false)}
                    disabled={busy}
                >
                    {t("approval.action.allow")}
                </Button>
                {showViewOnly && (
                    <Button
                        variant={"secondary"}
                        size={"md"}
                        className={"w-full"}
                        onClick={() => respond(true, true)}
                        disabled={busy}
                    >
                        {t("approval.action.allowViewOnly")}
                    </Button>
                )}
                <Button
                    variant={"danger"}
                    size={"md"}
                    className={"w-full"}
                    onClick={() => respond(false, false)}
                    disabled={busy}
                >
                    {t("approval.action.deny")}
                </Button>
            </DialogActions>
        </ConfirmDialog>
    );
}
