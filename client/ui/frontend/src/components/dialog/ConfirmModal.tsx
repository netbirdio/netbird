import { ReactNode, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import * as Dialog from "@/components/dialog/Dialog";
import { Button } from "@/components/buttons/Button";
import { DialogHeading } from "@/components/dialog/DialogHeading";
import { DialogDescription } from "@/components/dialog/DialogDescription";
import { DialogActions } from "@/components/dialog/DialogActions";

type ConfirmModalProps = {
    open: boolean;
    title: ReactNode;
    description: ReactNode;
    confirmLabel: string;
    cancelLabel?: string;
    danger?: boolean;
    busy?: boolean;
    onConfirm: () => void;
    onCancel: () => void;
};

export const ConfirmModal = ({
    open,
    title,
    description,
    confirmLabel,
    cancelLabel,
    danger = false,
    busy = false,
    onConfirm,
    onCancel,
}: ConfirmModalProps) => {
    const { t } = useTranslation();

    // Retain last content so it survives Radix's close animation.
    type Snapshot = Pick<ConfirmModalProps, "title" | "description" | "confirmLabel" | "danger"> & {
        cancelLabel: string;
    };
    const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
    const resolvedCancel = cancelLabel ?? t("common.cancel");
    useEffect(() => {
        if (open) {
            setSnapshot({ title, description, confirmLabel, cancelLabel: resolvedCancel, danger });
        }
    }, [open, title, description, confirmLabel, resolvedCancel, danger]);

    const view = open
        ? { title, description, confirmLabel, cancelLabel: resolvedCancel, danger }
        : snapshot;

    return (
        <Dialog.Root
            open={open}
            onOpenChange={(next) => {
                if (!next && !busy) onCancel();
            }}
        >
            <Dialog.Content
                maxWidthClass="max-w-sm"
                showClose={false}
                className="py-5"
                onOpenAutoFocus={(e) => e.preventDefault()}
            >
                {view && (
                    <div className="flex flex-col gap-5 px-5">
                        <div className="flex flex-col gap-1 pl-1">
                            <DialogHeading align={"left"}>{view.title}</DialogHeading>
                            <DialogDescription align={"left"} className={"whitespace-pre-line"}>
                                {view.description}
                            </DialogDescription>
                        </div>

                        <DialogActions className={"flex-row justify-end gap-2.5"}>
                            <Button
                                variant={"secondary"}
                                size={"xs2"}
                                disabled={busy}
                                onClick={onCancel}
                            >
                                {view.cancelLabel}
                            </Button>
                            <Button
                                autoFocus
                                variant={view.danger ? "danger" : "primary"}
                                size={"xs2"}
                                disabled={busy}
                                onClick={onConfirm}
                            >
                                {view.confirmLabel}
                            </Button>
                        </DialogActions>
                    </div>
                )}
            </Dialog.Content>
        </Dialog.Root>
    );
};
