import { useTranslation } from "react-i18next";
import { cn } from "@/lib/cn";
import { formatBytes } from "@/lib/formatters";

// Enough to recognise which snippet is on the clipboard without turning the
// preview into a text editor; the box clamps to three lines on top of this.
const PREVIEW_CHARS = 280;

export const ClipboardPreview = ({ text, className }: { text: string; className?: string }) => {
    const { t } = useTranslation();
    const clipped = text.length > PREVIEW_CHARS;
    const bytes = new TextEncoder().encode(text).length;

    return (
        <div
            role={"group"}
            aria-label={t("files.send.clipboardPreview")}
            className={cn(
                "flex flex-col gap-1 rounded-md px-2 py-1.5",
                "border border-nb-gray-850 bg-nb-gray-930",
                className,
            )}
        >
            <p
                className={cn(
                    "m-0 whitespace-pre-wrap break-words text-[0.7rem] leading-snug",
                    "italic text-nb-gray-300",
                    // Three lines keeps the box from crowding out whatever it
                    // is embedded in.
                    "line-clamp-3",
                )}
            >
                {clipped ? `${text.slice(0, PREVIEW_CHARS)}…` : text}
            </p>
            <span className={"self-end text-[0.65rem] tabular-nums text-nb-gray-500"}>
                {formatBytes(bytes)}
            </span>
        </div>
    );
};
