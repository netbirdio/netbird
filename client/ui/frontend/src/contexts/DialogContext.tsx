import { createContext, ReactNode, useCallback, useContext, useRef, useState } from "react";
import { ConfirmModal } from "@/components/dialog/ConfirmModal";

// DialogContext exposes an imperative `confirm(...)` that resolves to a
// boolean — the in-app equivalent of the native warningDialog promise. The
// single <ConfirmModal/> lives here at the provider level, so call sites
// just `await confirm({...})` instead of each wiring up their own modal
// component + open/busy state.
//
//   const confirm = useConfirm();
//   if (await confirm({ title, description, confirmLabel })) { …do it… }
//
// Mounted once (outermost in AppLayout) so it's available in every in-window
// route across both the main and settings windows.
export type ConfirmOptions = {
    title: ReactNode;
    description: ReactNode;
    confirmLabel: string;
    /** Defaults to the shared "Cancel" string inside ConfirmModal. */
    cancelLabel?: string;
    /** Use the destructive (red) confirm button variant. */
    danger?: boolean;
};

type DialogContextValue = {
    confirm: (options: ConfirmOptions) => Promise<boolean>;
};

const DialogContext = createContext<DialogContextValue | null>(null);

export function DialogProvider({ children }: { children: ReactNode }) {
    const [open, setOpen] = useState(false);
    const [options, setOptions] = useState<ConfirmOptions | null>(null);
    const resolverRef = useRef<((result: boolean) => void) | null>(null);

    const confirm = useCallback((opts: ConfirmOptions) => {
        setOptions(opts);
        setOpen(true);
        return new Promise<boolean>((resolve) => {
            resolverRef.current = resolve;
        });
    }, []);

    // Resolve the pending promise and start the close animation. The options
    // stay in state so ConfirmModal still has content to render while it
    // animates out.
    const settle = (result: boolean) => {
        resolverRef.current?.(result);
        resolverRef.current = null;
        setOpen(false);
    };

    return (
        <DialogContext.Provider value={{ confirm }}>
            {children}
            <ConfirmModal
                open={open}
                title={options?.title ?? ""}
                description={options?.description ?? ""}
                confirmLabel={options?.confirmLabel ?? ""}
                cancelLabel={options?.cancelLabel}
                danger={options?.danger}
                onConfirm={() => settle(true)}
                onCancel={() => settle(false)}
            />
        </DialogContext.Provider>
    );
}

export const useConfirm = () => {
    const ctx = useContext(DialogContext);
    if (!ctx) throw new Error("useConfirm must be used within a DialogProvider");
    return ctx.confirm;
};
