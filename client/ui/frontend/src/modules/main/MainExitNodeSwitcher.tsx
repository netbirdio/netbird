import { forwardRef, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as Popover from "@radix-ui/react-popover";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { Command } from "cmdk";
import { Check, ChevronsUpDown, type LucideProps, SquareArrowUpRight } from "lucide-react";
import { cn } from "@/lib/cn";
import { TruncatedText } from "@/components/TruncatedText";
import { useNetworks } from "@/contexts/NetworksContext";
import { useStatus } from "@/contexts/StatusContext";

const NONE_VALUE = "__none__";

export const MainExitNodeSwitcher = () => {
    const { t } = useTranslation();
    const { status } = useStatus();
    const { exitNodes, toggleExitNode } = useNetworks();
    const active = exitNodes.find((n) => n.selected) ?? null;
    const isConnected = status?.status === "Connected";
    const hasAny = exitNodes.length > 0;
    const disabled = !isConnected || !hasAny;

    const [open, setOpen] = useState(false);
    const listRef = useRef<HTMLDivElement>(null);

    const handleTriggerKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
        if (open || disabled) return;
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            setOpen(true);
        }
    };

    const handleSelect = (next: string) => {
        setOpen(false);
        if (next === NONE_VALUE) {
            if (active)
                toggleExitNode(active.id, true).catch((err: unknown) =>
                    console.error("toggle exit node failed", err),
                );
            return;
        }
        if (active?.id === next) return;
        toggleExitNode(next, false).catch((err: unknown) =>
            console.error("toggle exit node failed", err),
        );
    };

    const title = active ? active.id : t("exitNodes.card.title");
    const activeDescription = active
        ? t("exitNodes.card.statusActive")
        : t("exitNodes.card.statusInactive");
    const description = hasAny ? activeDescription : t("exitNodes.empty.title");

    return (
        <Popover.Root open={open} onOpenChange={setOpen}>
            <Popover.Trigger asChild className={"wails-no-draggable"}>
                <ExitNodeTriggerCard
                    title={title}
                    description={description}
                    disabled={disabled}
                    active={!!active}
                    aria-label={t("exitNodes.dropdown.trigger")}
                    aria-haspopup={"listbox"}
                    aria-expanded={open}
                    onKeyDown={handleTriggerKeyDown}
                />
            </Popover.Trigger>
            <Popover.Portal>
                <Popover.Content
                    align={"center"}
                    side={"top"}
                    sideOffset={8}
                    collisionPadding={12}
                    onOpenAutoFocus={(e) => {
                        e.preventDefault();
                        listRef.current?.focus();
                    }}
                    style={{ width: "var(--radix-popover-trigger-width)" }}
                    className={cn(
                        "z-50 overflow-hidden rounded-lg border border-nb-gray-900 bg-nb-gray-935 p-1 text-nb-gray-200 shadow-lg select-none wails-no-draggable",
                        "data-[state=open]:animate-in data-[state=closed]:animate-out",
                        "data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
                        "data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95",
                        "data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2",
                        "data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2",
                    )}
                >
                    <Command
                        loop
                        shouldFilter={false}
                        onKeyDown={(e) => e.stopPropagation()}
                        className={"outline-none focus:outline-none focus-visible:outline-none"}
                    >
                        <Command.List
                            ref={listRef}
                            aria-label={t("exitNodes.dropdown.trigger")}
                            className={"outline-none focus:outline-none focus-visible:outline-none"}
                        >
                            <NoneRow isActive={!active} onSelect={() => handleSelect(NONE_VALUE)} />
                            {hasAny && <div className={"-mx-1 my-1 h-px bg-nb-gray-910"} />}
                            {hasAny && (
                                <ScrollArea.Root type={"auto"} className={"overflow-hidden -mx-1"}>
                                    <ScrollArea.Viewport className={"max-h-72 px-1"}>
                                        {exitNodes.map((n) => (
                                            <ExitNodeRow
                                                key={n.id}
                                                id={n.id}
                                                label={n.id}
                                                isActive={active?.id === n.id}
                                                onSelect={() => handleSelect(n.id)}
                                            />
                                        ))}
                                    </ScrollArea.Viewport>
                                    <ScrollArea.Scrollbar
                                        orientation={"vertical"}
                                        className={cn(
                                            "flex select-none touch-none transition-colors",
                                            "w-1.5 bg-transparent",
                                        )}
                                    >
                                        <ScrollArea.Thumb
                                            className={"flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700 relative"}
                                        />
                                    </ScrollArea.Scrollbar>
                                </ScrollArea.Root>
                            )}
                        </Command.List>
                    </Command>
                </Popover.Content>
            </Popover.Portal>
        </Popover.Root>
    );
};

type TriggerProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
    title: string;
    description: string;
    active?: boolean;
};

const ExitNodeTriggerCard = forwardRef<HTMLButtonElement, TriggerProps>(
    function ExitNodeTriggerCard(
        { title, description, disabled, active = false, className, ...props },
        ref,
    ) {
        return (
            <button
                ref={ref}
                type={"button"}
                tabIndex={0}
                disabled={disabled}
                className={cn(
                    "w-full flex items-center gap-3 p-2.5 pr-5 rounded-xl outline-none text-left",
                    "border border-nb-gray-920 bg-nb-gray-940",
                    "transition-colors duration-150",
                    "wails-no-draggable",
                    "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                    disabled
                        ? "opacity-60 cursor-not-allowed"
                        : "cursor-default hover:bg-nb-gray-935 hover:border-nb-gray-900 data-[state=open]:bg-nb-gray-935 data-[state=open]:border-nb-gray-900",
                    className,
                )}
                {...props}
            >
                <div
                    aria-hidden={"true"}
                    className={cn(
                        "h-9 w-9 rounded-md flex items-center justify-center shrink-0",
                        active
                            ? "bg-green-500/25 text-green-400"
                            : "bg-nb-gray-900 text-nb-gray-300",
                    )}
                >
                    <ExitNodeIcon size={14} />
                </div>
                <div className={"min-w-0 flex-1"}>
                    <span className={"block font-medium text-sm text-nb-gray-100 truncate"}>
                        {title}
                    </span>
                    <TruncatedText
                        text={description}
                        className={"block text-[0.85rem] font-medium text-nb-gray-400 truncate max-w-full"}
                    />
                </div>
                <ChevronsUpDown
                    size={16}
                    aria-hidden={"true"}
                    className={"text-nb-gray-400 shrink-0"}
                />
            </button>
        );
    },
);

type NoneRowProps = {
    isActive: boolean;
    onSelect: () => void;
};

const NoneRow = ({ isActive, onSelect }: NoneRowProps) => {
    const { t } = useTranslation();
    return (
        <Command.Item
            value={NONE_VALUE}
            onSelect={onSelect}
            className={cn(
                "flex gap-2 items-center px-2 py-2 pr-3",
                "rounded-md outline-none cursor-default text-sm",
                "data-[selected=true]:bg-nb-gray-900",
            )}
        >
            <span className={"min-w-0 flex-1 truncate"}>{t("exitNodes.dropdown.noneTitle")}</span>
            {isActive && <Check size={16} aria-hidden={"true"} className={"shrink-0 text-netbird"} />}
        </Command.Item>
    );
};

type ExitNodeRowProps = {
    id: string;
    label: string;
    isActive: boolean;
    onSelect: () => void;
};

const ExitNodeRow = ({ id, label, isActive, onSelect }: ExitNodeRowProps) => (
    <Command.Item
        value={id}
        onSelect={onSelect}
        className={cn(
            "flex gap-2 items-center px-2 py-2 pr-3",
            "rounded-md outline-none cursor-default text-sm",
            "data-[selected=true]:bg-nb-gray-900",
        )}
    >
        <span className={"min-w-0 flex-1 truncate"}>{label}</span>
        {isActive && <Check size={16} aria-hidden={"true"} className={"shrink-0 text-netbird"} />}
    </Command.Item>
);

const ExitNodeIcon = ({ size, ...props }: LucideProps) => (
    <SquareArrowUpRight
        {...props}
        size={typeof size === "number" ? size - 2 : size}
        className={cn("rotate-45", props.className)}
    />
);
