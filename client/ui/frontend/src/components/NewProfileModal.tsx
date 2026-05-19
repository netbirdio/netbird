import { FormEvent, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { PlusCircle } from "lucide-react";
import * as Dialog from "@/components/Dialog";
import { Input } from "@/components/Input";
import { Button } from "@/components/Button";

type Props = {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onCreate: (name: string) => void;
};

export const NewProfileModal = ({ open, onOpenChange, onCreate }: Props) => {
    const { t } = useTranslation();
    const [name, setName] = useState("");
    const [error, setError] = useState<string | null>(null);
    const inputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        if (!open) {
            setName("");
            setError(null);
        }
    }, [open]);

    const handleSubmit = (e: FormEvent) => {
        e.preventDefault();
        const trimmed = name.trim();
        if (trimmed.length === 0) {
            setError(t("profile.dialog.required"));
            inputRef.current?.focus();
            return;
        }
        onCreate(trimmed);
        onOpenChange(false);
    };

    const handleChange = (value: string) => {
        setName(value);
        if (error) setError(null);
    };

    return (
        <Dialog.Root open={open} onOpenChange={onOpenChange}>
            <Dialog.Content maxWidthClass="max-w-md" onOpenAutoFocus={(e) => e.preventDefault()}>
                <form onSubmit={handleSubmit}>
                    <div className="px-8">
                        <Dialog.Title>{t("profile.dialog.title")}</Dialog.Title>
                        <Dialog.Description className="mt-1">
                            {t("profile.dialog.description")}
                        </Dialog.Description>
                    </div>

                    <div className="px-8 pt-3">
                        <Input
                            ref={inputRef}
                            autoFocus
                            placeholder={t("profile.dialog.placeholder")}
                            value={name}
                            onChange={(e) => handleChange(e.target.value)}
                            error={error ?? undefined}
                        />
                    </div>

                    <Dialog.Footer separator={false} className="pt-4">
                        <Button
                            type="submit"
                            variant="primary"
                            size={"md"}
                            className="w-full"
                        >
                            <PlusCircle size={14} />
                            {t("profile.dialog.submit")}
                        </Button>
                    </Dialog.Footer>
                </form>
            </Dialog.Content>
        </Dialog.Root>
    );
};
