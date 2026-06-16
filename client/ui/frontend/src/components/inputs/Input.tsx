import { cva, VariantProps } from "class-variance-authority";
import { Check, ChevronDown, ChevronUp, Copy, Eye, EyeOff } from "lucide-react";
import {
    forwardRef,
    InputHTMLAttributes,
    ReactNode,
    useEffect,
    useId,
    useRef,
    useState,
} from "react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/cn";
import { Label } from "@/components/typography/Label";

type InputVariants = VariantProps<typeof inputVariants>;

export interface InputProps extends InputHTMLAttributes<HTMLInputElement>, InputVariants {
    label?: string;
    customPrefix?: ReactNode;
    customSuffix?: ReactNode;
    maxWidthClass?: string;
    icon?: ReactNode;
    error?: string;
    warning?: string;
    prefixClassName?: string;
    showPasswordToggle?: boolean;
    copy?: boolean;
}

const inputVariants = cva("", {
    variants: {
        variant: {
            default: [
                "dark:bg-nb-gray-900 dark:placeholder:text-neutral-400/70 placeholder:text-neutral-500 border-neutral-200 dark:border-nb-gray-700",
                "ring-offset-neutral-200/20 dark:ring-offset-neutral-950/50 dark:focus-visible:ring-neutral-500/20 focus-visible:ring-neutral-300/10",
            ],
            darker: [
                "dark:bg-nb-gray-920 dark:placeholder:text-neutral-400/70 placeholder:text-neutral-500 border-neutral-300 dark:border-nb-gray-800",
                "ring-offset-neutral-200/20 dark:ring-offset-neutral-950/50 dark:focus-visible:ring-neutral-500/20 focus-visible:ring-neutral-300/10",
            ],
            error: [
                "dark:bg-nb-gray-900 dark:placeholder:text-neutral-400/70 placeholder:text-neutral-500 border-neutral-200 dark:border-red-500 text-red-500",
                "ring-offset-red-500/10 dark:ring-offset-red-500/10 dark:focus-visible:ring-red-500/10 focus-visible:ring-red-500/10",
            ],
            warning: [
                "dark:bg-nb-gray-900 dark:placeholder:text-neutral-400/70 placeholder:text-neutral-500 border-neutral-200 dark:border-orange-400 text-orange-400",
                "ring-offset-orange-400/10 dark:ring-offset-orange-400/10 dark:focus-visible:ring-orange-400/10 focus-visible:ring-orange-400/10",
            ],
        },
        prefixSuffixVariant: {
            default: [
                "dark:bg-nb-gray-900 border-neutral-200 dark:border-nb-gray-700 text-nb-gray-300",
            ],
            error: ["dark:bg-nb-gray-900 border-red-500 text-nb-gray-300 text-red-500"],
        },
    },
});

function computeNextStepValue(el: HTMLInputElement, delta: 1 | -1): number {
    const stepAttr = el.step === "" ? 1 : Number(el.step);
    const step = Number.isFinite(stepAttr) && stepAttr > 0 ? stepAttr : 1;
    const min = el.min === "" ? -Infinity : Number(el.min);
    const max = el.max === "" ? Infinity : Number(el.max);
    const current = el.value === "" ? 0 : Number(el.value);
    let next = (Number.isFinite(current) ? current : 0) + delta * step;
    if (next < min) next = min;
    if (next > max) next = max;
    return next;
}

function buildInputClassName(
    opts: Readonly<{
        variant: InputVariants["variant"];
        hasCustomPrefix: boolean;
        hasSuffix: boolean;
        hasIcon: boolean;
        readOnly?: boolean;
        showStepper: boolean;
        className?: string;
    }>,
): string {
    return cn(
        inputVariants({ variant: opts.variant }),
        "flex h-[40px] w-full rounded-md bg-white px-3 py-2 text-sm select-text",
        "file:bg-transparent file:text-sm file:font-medium file:border-0",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2",
        "disabled:cursor-not-allowed disabled:opacity-40",
        opts.hasCustomPrefix && "!border-l-0 !rounded-l-none",
        opts.hasSuffix && "!pr-9",
        opts.hasIcon && "!pl-10",
        "border",
        opts.readOnly && "!bg-nb-gray-910 text-nb-gray-350 !border-nb-gray-800",
        opts.showStepper &&
            "!rounded-r-none [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none [-moz-appearance:textfield]",
        opts.className,
    );
}

function InputAffix({
    content,
    error,
    disabled,
    className,
}: Readonly<{ content: ReactNode; error?: string; disabled?: boolean; className?: string }>) {
    return (
        <div
            className={cn(
                inputVariants({ prefixSuffixVariant: error ? "error" : "default" }),
                "flex h-[40px] w-auto rounded-l-md bg-white px-3 py-2 text-sm",
                "border items-center whitespace-nowrap",
                disabled && "opacity-40",
                className,
            )}
        >
            {content}
        </div>
    );
}

function InputIconSlot({ icon, disabled }: Readonly<{ icon: ReactNode; disabled?: boolean }>) {
    return (
        <div
            className={cn(
                "absolute left-0 top-0 h-full flex items-center text-xs dark:text-nb-gray-300 pl-3 leading-[0]",
                disabled && "opacity-40",
            )}
        >
            {icon}
        </div>
    );
}

function InputSuffixSlot({
    suffix,
    disabled,
}: Readonly<{ suffix: ReactNode; disabled?: boolean }>) {
    return (
        <div
            className={cn(
                "absolute right-0 top-0 h-full flex items-center text-xs dark:text-nb-gray-300 pr-3 leading-[0] select-none pointer-events-none",
                disabled && "opacity-30",
            )}
        >
            {suffix}
        </div>
    );
}

function NumberStepper({
    error,
    disabled,
    onStep,
}: Readonly<{ error?: string; disabled?: boolean; onStep: (delta: 1 | -1) => void }>) {
    const { t } = useTranslation();
    return (
        <div
            className={cn(
                "flex flex-col h-[40px] shrink-0 overflow-hidden",
                "border border-l-0 rounded-r-md",
                "border-neutral-200 dark:border-nb-gray-700 dark:bg-nb-gray-900",
                error && "dark:border-red-500",
                disabled && "opacity-40 pointer-events-none",
            )}
        >
            <button
                type="button"
                tabIndex={-1}
                aria-label={t("common.increase")}
                onClick={() => onStep(1)}
                className="flex-1 flex items-center justify-center w-9 hover:bg-nb-gray-800 transition-colors text-nb-gray-300 cursor-default"
            >
                <ChevronUp size={12} />
            </button>
            <button
                type="button"
                tabIndex={-1}
                aria-label={t("common.decrease")}
                onClick={() => onStep(-1)}
                className={cn(
                    "flex-1 flex items-center justify-center w-9 hover:bg-nb-gray-800 transition-colors text-nb-gray-300 cursor-default",
                    "border-t border-neutral-200 dark:border-nb-gray-700",
                )}
            >
                <ChevronDown size={12} />
            </button>
        </div>
    );
}

function FieldMessage({ error, warning }: Readonly<{ error?: string; warning?: string }>) {
    if (!error && !warning) return null;
    return (
        <span
            className={cn(
                "text-xs mt-2 inline-flex items-center gap-1",
                error ? "text-red-500" : "text-orange-400",
            )}
        >
            {error ?? warning}
        </span>
    );
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
    {
        className,
        type,
        label,
        customSuffix,
        customPrefix,
        icon,
        maxWidthClass = "",
        error,
        warning,
        variant = "default",
        prefixClassName,
        showPasswordToggle = false,
        copy = false,
        id,
        ...props
    },
    ref,
) {
    const { t } = useTranslation();
    const [showPassword, setShowPassword] = useState(false);
    const [copied, setCopied] = useState(false);
    const isPasswordType = type === "password";
    const inputType = isPasswordType && showPassword ? "text" : type;
    const isNumber = type === "number";

    const reactId = useId();
    const inputId = id ?? (label ? `input-${reactId}` : undefined);

    const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
    useEffect(
        () => () => {
            if (copyTimer.current) clearTimeout(copyTimer.current);
        },
        [],
    );

    const internalRef = useRef<HTMLInputElement | null>(null);
    const setRefs = (el: HTMLInputElement | null) => {
        internalRef.current = el;
        if (typeof ref === "function") ref(el);
        else if (ref) ref.current = el;
    };

    const stepBy = (delta: 1 | -1) => {
        const el = internalRef.current;
        if (!el || el.disabled || el.readOnly) return;
        const setter = Object.getOwnPropertyDescriptor(
            globalThis.HTMLInputElement.prototype,
            "value",
        )?.set;
        const next = computeNextStepValue(el, delta);
        setter?.call(el, String(next));
        el.dispatchEvent(new Event("input", { bubbles: true }));
    };

    const passwordToggle =
        isPasswordType && showPasswordToggle ? (
            <button
                type="button"
                onClick={() => setShowPassword((s) => !s)}
                className="hover:text-white transition-all pointer-events-auto"
                aria-label={t("common.togglePasswordVisibility")}
            >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
        ) : null;

    const onCopy = async () => {
        const text = props.value == null ? (internalRef.current?.value ?? "") : String(props.value);
        if (!text) return;
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            if (copyTimer.current) clearTimeout(copyTimer.current);
            copyTimer.current = setTimeout(() => setCopied(false), 1500);
        } catch (e) {
            console.warn("copy to clipboard failed", e);
        }
    };

    const copyToggle = copy ? (
        <button
            type="button"
            onClick={onCopy}
            className="hover:text-white transition-all pointer-events-auto"
            aria-label={t("common.copy")}
        >
            {copied ? <Check size={16} /> : <Copy size={16} />}
        </button>
    ) : null;

    const suffix = passwordToggle || copyToggle || customSuffix;
    const showStepper = isNumber;
    const warningVariant = warning ? "warning" : variant;
    const resolvedVariant = error ? "error" : warningVariant;

    const inputClassName = buildInputClassName({
        variant: resolvedVariant,
        hasCustomPrefix: !!customPrefix,
        hasSuffix: !!suffix,
        hasIcon: !!icon,
        readOnly: props.readOnly,
        showStepper,
        className,
    });

    return (
        <div className="flex flex-col w-full min-w-0">
            {label && <Label htmlFor={inputId}>{label}</Label>}
            <div className={cn("flex relative h-[40px] w-full", maxWidthClass)}>
                {customPrefix && (
                    <InputAffix
                        content={customPrefix}
                        error={error}
                        disabled={props.disabled}
                        className={prefixClassName}
                    />
                )}

                {icon && <InputIconSlot icon={icon} disabled={props.disabled} />}

                <div className="relative flex flex-grow min-w-0">
                    <input
                        id={inputId}
                        type={inputType}
                        ref={setRefs}
                        {...props}
                        className={inputClassName}
                    />

                    {suffix && <InputSuffixSlot suffix={suffix} disabled={props.disabled} />}
                </div>

                {showStepper && (
                    <NumberStepper error={error} disabled={props.disabled} onStep={stepBy} />
                )}
            </div>
            <FieldMessage error={error} warning={warning} />
        </div>
    );
});

export default Input;
