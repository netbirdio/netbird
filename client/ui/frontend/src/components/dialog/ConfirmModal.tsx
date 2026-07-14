import { type ReactNode } from "react";
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
    const resolvedCancel = cancelLabel ?? t("common.cancel");

    const srTitle = typeof title === "string" ? title : undefined;
    const srDescription = typeof description === "string" ? description : undefined;

    return (
        <Dialog.Root
            open={open}
            onOpenChange={(next) => {
                if (!next && !busy) onCancel();
            }}
        >
            <Dialog.Content
                maxWidthClass={"max-w-sm"}
                showClose={false}
                className={"py-5"}
                srTitle={srTitle}
                srDescription={srDescription}
                onOpenAutoFocus={(e) => e.preventDefault()}
            >
                <div className={"flex flex-col gap-5 px-5"}>
                    <div className={"flex flex-col gap-1 pl-1"}>
                        <DialogHeading align={"left"}>{title}</DialogHeading>
                        <DialogDescription align={"left"} className={"whitespace-pre-line"}>
                            {description}
                        </DialogDescription>
                    </div>

                    <DialogActions className={"flex-row justify-end gap-2.5"}>
                        <Button
                            variant={"secondary"}
                            size={"sm"}
                            disabled={busy}
                            onClick={onCancel}
                        >
                            {resolvedCancel}
                        </Button>
                        <Button
                            autoFocus
                            variant={danger ? "danger" : "primary"}
                            size={"sm"}
                            disabled={busy}
                            onClick={onConfirm}
                        >
                            {confirmLabel}
                        </Button>
                    </DialogActions>
                </div>
            </Dialog.Content>
        </Dialog.Root>
    );
};
