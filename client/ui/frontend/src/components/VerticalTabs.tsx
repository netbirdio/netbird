import { ComponentType, ReactNode, forwardRef } from "react";
import * as Tabs from "@radix-ui/react-tabs";
import { LucideProps } from "lucide-react";
import { cn } from "@/lib/cn";

const Root = forwardRef<
    HTMLDivElement,
    Omit<Tabs.TabsProps, "orientation">
>(function VerticalTabsRoot({ className, ...props }, ref) {
    return (
        <Tabs.Root
            ref={ref}
            orientation={"vertical"}
            className={cn("flex flex-1 min-h-0 gap-4", className)}
            {...props}
        />
    );
});

const List = forwardRef<HTMLDivElement, Tabs.TabsListProps>(
    function VerticalTabsList({ className, ...props }, ref) {
        return (
            <Tabs.List
                ref={ref}
                className={cn("w-full flex flex-col gap-1", className)}
                {...props}
            />
        );
    },
);

type TriggerProps = Tabs.TabsTriggerProps & {
    icon: ComponentType<LucideProps>;
    title: string;
    iconSize?: number;
    adornment?: ReactNode;
};

const Trigger = forwardRef<HTMLButtonElement, TriggerProps>(
    function VerticalTabsTrigger(
        { icon: Icon, title, iconSize = 16, adornment, className, ...props },
        ref,
    ) {
        return (
            <Tabs.Trigger
                ref={ref}
                className={cn(
                    "group w-full flex items-center gap-3 py-2.5 px-2 rounded-lg cursor-default outline-none text-left",
                    "transition-colors duration-150",
                    "data-[state=active]:bg-nb-gray-930",
                    "data-[state=inactive]:hover:bg-nb-gray-935",
                    className,
                )}
                {...props}
            >
                <Icon
                    size={iconSize}
                    className={cn(
                        "shrink-0 ml-2 transition-colors duration-150",
                        "text-nb-gray-400 group-data-[state=active]:text-nb-gray-100",
                    )}
                />
                <h2
                    className={cn(
                        "font-medium text-sm truncate min-w-0 transition-colors duration-150",
                        "text-nb-gray-400 group-data-[state=active]:text-nb-gray-100",
                    )}
                >
                    {title}
                </h2>
                {adornment && <div className={"ml-auto mr-2 shrink-0"}>{adornment}</div>}
            </Tabs.Trigger>
        );
    },
);

const Content = forwardRef<HTMLDivElement, Tabs.TabsContentProps>(
    function VerticalTabsContent({ className, ...props }, ref) {
        return (
            <Tabs.Content
                ref={ref}
                className={cn("outline-none", className)}
                {...props}
            />
        );
    },
);

export const VerticalTabs = Object.assign(Root, { List, Trigger, Content });
