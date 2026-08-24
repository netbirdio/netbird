import { type ComponentType, type ReactNode, forwardRef } from "react";
import * as Tabs from "@radix-ui/react-tabs";
import { type LucideProps } from "lucide-react";
import { cn } from "@/lib/cn";
import { useFocusVisible } from "@/hooks/useFocusVisible";

const Root = forwardRef<HTMLDivElement, Omit<Tabs.TabsProps, "orientation">>(
    function VerticalTabsRoot({ className, ...props }, ref) {
        return (
            <Tabs.Root
                ref={ref}
                orientation={"vertical"}
                className={cn("flex min-h-0 flex-1", className)}
                {...props}
            />
        );
    },
);

const List = forwardRef<HTMLDivElement, Tabs.TabsListProps>(function VerticalTabsList(
    { className, ...props },
    ref,
) {
    return (
        <Tabs.List
            ref={ref}
            className={cn("flex w-full flex-col gap-1 p-5 pr-0", className)}
            {...props}
        />
    );
});

type TriggerProps = Tabs.TabsTriggerProps & {
    icon: ComponentType<LucideProps>;
    title: string;
    iconSize?: number;
    adornment?: ReactNode;
};

const Trigger = forwardRef<HTMLButtonElement, TriggerProps>(function VerticalTabsTrigger(
    { icon: Icon, title, iconSize = 16, adornment, className, ...props },
    ref,
) {
    const isFocusVisible = useFocusVisible();
    return (
        <Tabs.Trigger
            ref={ref}
            className={cn(
                "group flex w-full cursor-default items-center gap-3 rounded-lg px-2 py-2.5 text-left outline-none",
                "transition-colors duration-150",
                "data-[state=active]:bg-nb-gray-930",
                "data-[state=inactive]:hover:bg-nb-gray-935",
                isFocusVisible &&
                    "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                className,
            )}
            {...props}
        >
            <Icon
                size={iconSize}
                aria-hidden={"true"}
                className={cn(
                    "ml-2 shrink-0 transition-colors duration-150",
                    "text-nb-gray-400 group-data-[state=active]:text-nb-gray-100",
                )}
            />
            <span
                className={cn(
                    "min-w-0 truncate text-sm font-medium transition-colors duration-150",
                    "text-nb-gray-400 group-data-[state=active]:text-nb-gray-100",
                )}
            >
                {title}
            </span>
            {adornment && (
                <div aria-hidden={"true"} className={"ml-auto mr-2 shrink-0"}>
                    {adornment}
                </div>
            )}
        </Tabs.Trigger>
    );
});

const Content = forwardRef<HTMLDivElement, Tabs.TabsContentProps>(function VerticalTabsContent(
    { className, ...props },
    ref,
) {
    return (
        <Tabs.Content
            ref={ref}
            tabIndex={-1}
            className={cn("outline-none", className)}
            {...props}
        />
    );
});

export const VerticalTabs = Object.assign(Root, { List, Trigger, Content });
