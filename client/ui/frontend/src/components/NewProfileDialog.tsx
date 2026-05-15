import { FormEvent, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import * as Dialog from "@/components/Dialog";
import { Input } from "@/components/Input";
import { Button } from "@/components/Button";

type Props = {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onCreate: (name: string) => void;
};

export const NewProfileDialog = ({ open, onOpenChange, onCreate }: Props) => {
    const { t } = useTranslation();
    const [name, setName] = useState("");

    useEffect(() => {
        if (!open) setName("");
    }, [open]);

    const trimmed = name.trim();
    const canSubmit = trimmed.length > 0;

    const handleSubmit = (e: FormEvent) => {
        e.preventDefault();
        if (!canSubmit) return;
        onCreate(trimmed);
        onOpenChange(false);
    };

    return (
        <Dialog.Root open={open} onOpenChange={onOpenChange}>
            <Dialog.Content
                maxWidthClass="max-w-md"
                onOpenAutoFocus={(e) => e.preventDefault()}
            >
                <form onSubmit={handleSubmit}>
                    <div className="px-8 pt-2">
                        <Dialog.Title>{t("profile.dialog.title")}</Dialog.Title>
                        <Dialog.Description>
                            {t("profile.dialog.description")}
                        </Dialog.Description>
                    </div>

                    <div className="px-8 pt-3">
                        <Input
                            autoFocus
                            placeholder={t("profile.dialog.placeholder")}
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                        />
                    </div>

                    <Dialog.Footer>
                        <Button
                            type="button"
                            variant="secondary"
                            onClick={() => onOpenChange(false)}
                        >
                            {t("common.cancel")}
                        </Button>
                        <Button
                            type="submit"
                            variant="primary"
                            disabled={!canSubmit}
                        >
                            {t("common.create")}
                        </Button>
                    </Dialog.Footer>
                </form>
            </Dialog.Content>
        </Dialog.Root>
    );
};
