import { FormEvent, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { PlusCircle } from "lucide-react";
import * as Dialog from "@/components/dialog/Dialog";
import { Input } from "@/components/inputs/Input";
import { Button } from "@/components/buttons/Button";

type Props = {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onCreate: (name: string) => void;
};

// Mirror of the daemon's profilemanager.sanitizeProfileName rule
// (client/internal/profilemanager/profilemanager.go): only letters, digits,
// `_` and `-` survive on the Go side. We additionally lowercase and convert
// spaces to `-` so what the user sees in the input is exactly what the
// daemon will store — otherwise the daemon silently sanitizes ("my profile"
// → "myprofile") while the UI keeps the raw name in flight, which spawns a
// ghost row and breaks subsequent delete.
const sanitizeProfileInput = (value: string): string =>
    value
        .toLowerCase()
        .replace(/\s+/g, "-")
        .replace(/[^a-z0-9_-]/g, "");

export const ProfileCreationModal = ({ open, onOpenChange, onCreate }: Props) => {
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
        const sanitized = sanitizeProfileInput(name);
        if (sanitized.length === 0) {
            setError(t("profile.dialog.required"));
            inputRef.current?.focus();
            return;
        }
        onCreate(sanitized);
        onOpenChange(false);
    };

    const handleChange = (value: string) => {
        setName(sanitizeProfileInput(value));
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
                            maxLength={64}
                            spellCheck={false}
                            autoComplete="off"
                            autoCapitalize="off"
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
