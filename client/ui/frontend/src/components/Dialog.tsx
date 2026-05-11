import {
    forwardRef,
    ComponentPropsWithoutRef,
    ElementRef,
    HTMLAttributes,
} from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { VisuallyHidden } from "@radix-ui/react-visually-hidden";
import { X } from "lucide-react";
import { cn } from "@/lib/cn";

export const Root = DialogPrimitive.Root;
export const Trigger = DialogPrimitive.Trigger;
export const Close = DialogPrimitive.Close;
export const Portal = DialogPrimitive.Portal;

export const Overlay = forwardRef<
    ElementRef<typeof DialogPrimitive.Overlay>,
    ComponentPropsWithoutRef<typeof DialogPrimitive.Overlay>
>(function DialogOverlay({ className, ...props }, ref) {
    return (
        <DialogPrimitive.Overlay
            ref={ref}
            className={cn(
                "fixed inset-0 z-50 grid place-items-start overflow-y-auto py-16",
                "bg-black/40 backdrop-blur-sm",
                "data-[state=open]:animate-in data-[state=closed]:animate-out",
                "data-[state=open]:fade-in-0 data-[state=closed]:fade-out-0",
                "duration-150 ease-out",
                className,
            )}
            style={{ scrollbarGutter: "stable both-edges" }}
            {...props}
        />
    );
});

type ContentProps = ComponentPropsWithoutRef<typeof DialogPrimitive.Content> & {
    showClose?: boolean;
    maxWidthClass?: string;
};

export const Content = forwardRef<
    ElementRef<typeof DialogPrimitive.Content>,
    ContentProps
>(function DialogContent(
    {
        className,
        children,
        showClose = true,
        maxWidthClass = "max-w-md",
        ...props
    },
    ref,
) {
    return (
        <DialogPrimitive.Portal>
            <Overlay>
                <DialogPrimitive.Content
                    ref={ref}
                    className={cn(
                        "mx-auto relative z-[52] w-full outline-none ring-0",
                        "focus:outline-none focus-visible:outline-none focus:ring-0 focus-visible:ring-0",
                        "border border-nb-gray-900 bg-nb-gray py-6 shadow-2xl rounded-lg",
                        "data-[state=open]:animate-in data-[state=closed]:animate-out",
                        "data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
                        "data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95",
                        "data-[state=closed]:slide-out-to-left-1 data-[state=open]:slide-in-from-left-1",
                        "duration-150 ease-out",
                        maxWidthClass,
                        className,
                    )}
                    onClick={(e) => e.stopPropagation()}
                    {...props}
                >
                    <VisuallyHidden asChild>
                        <DialogPrimitive.Title>Dialog</DialogPrimitive.Title>
                    </VisuallyHidden>
                    {children}
                    {showClose && (
                        <DialogPrimitive.Close
                            className={cn(
                                "absolute right-4 top-4 z-10 rounded-sm opacity-70 transition-opacity",
                                "hover:opacity-100 focus:outline-none disabled:pointer-events-none",
                                "text-nb-gray-300",
                            )}
                            aria-label="Close"
                        >
                            <X className="h-4 w-4" />
                        </DialogPrimitive.Close>
                    )}
                </DialogPrimitive.Content>
            </Overlay>
        </DialogPrimitive.Portal>
    );
});

export const Title = forwardRef<
    ElementRef<typeof DialogPrimitive.Title>,
    ComponentPropsWithoutRef<typeof DialogPrimitive.Title>
>(function DialogTitle({ className, ...props }, ref) {
    return (
        <DialogPrimitive.Title
            ref={ref}
            className={cn(
                "text-md font-semibold leading-none tracking-tight text-nb-gray-50",
                className,
            )}
            {...props}
        />
    );
});

export const Description = forwardRef<
    ElementRef<typeof DialogPrimitive.Description>,
    ComponentPropsWithoutRef<typeof DialogPrimitive.Description>
>(function DialogDescription({ className, ...props }, ref) {
    return (
        <DialogPrimitive.Description
            ref={ref}
            className={cn(
                "text-sm text-nb-gray-400 mt-2 leading-snug",
                className,
            )}
            {...props}
        />
    );
});

type FooterProps = HTMLAttributes<HTMLDivElement> & {
    separator?: boolean;
};

export const Footer = ({
    className,
    separator = true,
    ...props
}: FooterProps) => (
    <div className={cn(separator && "border-t border-nb-gray-900 mt-6")}>
        <div
            className={cn(
                "flex flex-col-reverse sm:flex-row sm:justify-end sm:gap-3",
                "px-8 pt-6",
                className,
            )}
            {...props}
        />
    </div>
);
