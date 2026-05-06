import { FormEvent, useEffect, useState } from "react";
import * as Dialog from "@/components/Dialog";
import { Input } from "@/components/Input";
import { Button } from "@/components/Button";

type Props = {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onCreate: (name: string) => void;
};

export const NewProfileDialog = ({ open, onOpenChange, onCreate }: Props) => {
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
                        <Dialog.Title>New Profile</Dialog.Title>
                        <Dialog.Description>
                            Profiles let you keep separate NetBird connections
                            side by side. Give your profile a memorable name.
                        </Dialog.Description>
                    </div>

                    <div className="px-8 pt-3">
                        <Input
                            autoFocus
                            placeholder="e.g. Work"
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
                            Cancel
                        </Button>
                        <Button
                            type="submit"
                            variant="primary"
                            disabled={!canSubmit}
                        >
                            Create
                        </Button>
                    </Dialog.Footer>
                </form>
            </Dialog.Content>
        </Dialog.Root>
    );
};
