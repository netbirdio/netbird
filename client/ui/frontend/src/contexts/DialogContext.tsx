import {
    createContext,
    type ReactNode,
    useCallback,
    useContext,
    useMemo,
    useRef,
    useState,
} from "react";
import { ConfirmModal } from "@/components/dialog/ConfirmModal";
import i18next from "@/lib/i18n";

// Nothing on the daemon path carries a deadline, so a hung call would leave the
// modal spinning with no way out. Cancel comes back once the wait stops looking
// normal, and the wait is abandoned entirely at the deadline.
const CANCELLABLE_AFTER_MS = 5_000;
const TIMEOUT_MS = 30_000;

const withTimeout = async (action: () => Promise<unknown>) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const expiry = new Promise<never>((_, reject) => {
        timer = setTimeout(
            () => reject(new Error(i18next.t("error.daemon_unreachable"))),
            TIMEOUT_MS,
        );
    });
    try {
        await Promise.race([action(), expiry]);
    } finally {
        clearTimeout(timer);
    }
};

export type ConfirmOptions = {
    title: ReactNode;
    description: ReactNode;
    confirmLabel: string;
    cancelLabel?: string;
    danger?: boolean;
    onConfirm?: () => Promise<unknown>;
};

type DialogContextValue = {
    confirm: (options: ConfirmOptions) => Promise<boolean>;
};

const DialogContext = createContext<DialogContextValue | null>(null);

type Settler = { resolve: (result: boolean) => void; reject: (reason: unknown) => void };

export function DialogProvider({ children }: Readonly<{ children: ReactNode }>) {
    const [open, setOpen] = useState(false);
    const [busy, setBusy] = useState(false);
    const [stalled, setStalled] = useState(false);
    const [options, setOptions] = useState<ConfirmOptions | null>(null);
    const resolverRef = useRef<Settler | null>(null);

    const confirm = useCallback((opts: ConfirmOptions) => {
        setOptions(opts);
        setOpen(true);
        return new Promise<boolean>((resolve, reject) => {
            resolverRef.current = { resolve, reject };
        });
    }, []);

    const take = (expected?: Settler | null) => {
        const settler = resolverRef.current;
        if (expected && settler !== expected) return null;
        resolverRef.current = null;
        setBusy(false);
        setStalled(false);
        setOpen(false);
        return settler;
    };

    const handleConfirm = async () => {
        const action = options?.onConfirm;
        if (!action) {
            take()?.resolve(true);
            return;
        }
        const dispatched = resolverRef.current;
        setBusy(true);
        const stallTimer = setTimeout(() => setStalled(true), CANCELLABLE_AFTER_MS);
        try {
            await withTimeout(action);
            take(dispatched)?.resolve(true);
        } catch (e) {
            take(dispatched)?.reject(e);
        } finally {
            clearTimeout(stallTimer);
        }
    };

    const value = useMemo<DialogContextValue>(() => ({ confirm }), [confirm]);

    return (
        <DialogContext.Provider value={value}>
            {children}
            <ConfirmModal
                open={open}
                title={options?.title ?? ""}
                description={options?.description ?? ""}
                confirmLabel={options?.confirmLabel ?? ""}
                cancelLabel={options?.cancelLabel}
                danger={options?.danger}
                busy={busy}
                cancellable={!busy || stalled}
                onConfirm={() => void handleConfirm()}
                onCancel={() => take()?.resolve(false)}
            />
        </DialogContext.Provider>
    );
}

export const useConfirm = () => {
    const ctx = useContext(DialogContext);
    if (!ctx) throw new Error("useConfirm must be used within a DialogProvider");
    return ctx.confirm;
};
