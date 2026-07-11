import {
    forwardRef,
    type ComponentPropsWithoutRef,
    type ElementRef,
    type HTMLAttributes,
} from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { VisuallyHidden } from "@radix-ui/react-visually-hidden";
import { X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/cn";

export const Root = DialogPrimitive.Root;

type OverlayProps = ComponentPropsWithoutRef<typeof DialogPrimitive.Overlay> & {
    exitAnimation?: boolean;
};

const Overlay = forwardRef<ElementRef<typeof DialogPrimitive.Overlay>, OverlayProps>(
    function DialogOverlay({ className, exitAnimation = false, ...props }, ref) {
        return (
            <DialogPrimitive.Overlay
                ref={ref}
                className={cn(
                    "fixed inset-0 z-50 grid items-center justify-items-center overflow-y-auto px-10 py-16",
                    "bg-black/60",
                    "data-[state=open]:animate-in data-[state=open]:fade-in-0",
                    exitAnimation &&
                        "data-[state=closed]:animate-out data-[state=closed]:fade-out-0",
                    "duration-150 ease-out",
                    className,
                )}
                {...props}
            />
        );
    },
);

type ContentProps = ComponentPropsWithoutRef<typeof DialogPrimitive.Content> & {
    showClose?: boolean;
    maxWidthClass?: string;
    exitAnimation?: boolean;
    srTitle?: string;
    srDescription?: string;
};

export const Content = forwardRef<ElementRef<typeof DialogPrimitive.Content>, ContentProps>(
    function DialogContent(
        {
            className,
            children,
            showClose = true,
            maxWidthClass = "max-w-md",
            exitAnimation = false,
            srTitle,
            srDescription,
            ...props
        },
        ref,
    ) {
        const { t } = useTranslation();
        return (
            <DialogPrimitive.Portal>
                <Overlay exitAnimation={exitAnimation}>
                    <DialogPrimitive.Content
                        ref={ref}
                        className={cn(
                            "relative z-[52] mx-auto w-full outline-none ring-0",
                            "focus:outline-none focus:ring-0 focus-visible:outline-none focus-visible:ring-0",
                            "rounded-lg border border-nb-gray-900 bg-nb-gray py-7 shadow-2xl",
                            "data-[state=open]:animate-in data-[state=open]:fade-in-0",
                            "data-[state=open]:zoom-in-95 data-[state=open]:slide-in-from-left-1",
                            exitAnimation &&
                                "data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 data-[state=closed]:slide-out-to-left-1",
                            "duration-150 ease-out",
                            maxWidthClass,
                            className,
                        )}
                        onClick={(e) => e.stopPropagation()}
                        {...props}
                    >
                        <VisuallyHidden asChild>
                            <DialogPrimitive.Title>
                                {srTitle ?? t("common.netbird")}
                            </DialogPrimitive.Title>
                        </VisuallyHidden>
                        {srDescription && (
                            <VisuallyHidden asChild>
                                <DialogPrimitive.Description>
                                    {srDescription}
                                </DialogPrimitive.Description>
                            </VisuallyHidden>
                        )}
                        {children}
                        {showClose && (
                            <DialogPrimitive.Close
                                className={cn(
                                    "absolute right-3 top-3 z-10 rounded-md p-3 transition-colors",
                                    "text-nb-gray-300 hover:text-nb-gray-100",
                                    "focus:outline-none disabled:pointer-events-none",
                                )}
                                aria-label={t("common.close")}
                            >
                                <X className={"h-4 w-4"} aria-hidden={"true"} />
                            </DialogPrimitive.Close>
                        )}
                    </DialogPrimitive.Content>
                </Overlay>
            </DialogPrimitive.Portal>
        );
    },
);

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
            className={cn("mt-2 text-sm leading-snug text-nb-gray-400", className)}
            {...props}
        />
    );
});

type FooterProps = HTMLAttributes<HTMLDivElement> & {
    separator?: boolean;
};

export const Footer = ({ className, separator = true, ...props }: FooterProps) => (
    <div className={cn(separator && "mt-6 border-t border-nb-gray-900")}>
        <div
            className={cn(
                "flex flex-col-reverse gap-3 sm:flex-row sm:justify-end",
                "[&>*]:w-full sm:[&>*]:w-auto",
                "px-8 pt-6",
                className,
            )}
            {...props}
        />
    </div>
);
