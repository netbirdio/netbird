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

export type ConfirmOptions = {
    title: ReactNode;
    description: ReactNode;
    confirmLabel: string;
    cancelLabel?: string;
    danger?: boolean;
};

type DialogContextValue = {
    confirm: (options: ConfirmOptions) => Promise<boolean>;
};

const DialogContext = createContext<DialogContextValue | null>(null);

export function DialogProvider({ children }: Readonly<{ children: ReactNode }>) {
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

    const settle = (result: boolean) => {
        resolverRef.current?.(result);
        resolverRef.current = null;
        setOpen(false);
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
