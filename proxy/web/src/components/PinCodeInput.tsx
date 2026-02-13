import { cn } from "@/utils/helpers";
import React, {
  useRef,
  type KeyboardEvent,
  type ClipboardEvent,
  forwardRef,
  useImperativeHandle,
} from "react";

export interface PinCodeInputRef {
  focus: () => void;
}

interface Props {
  value: string;
  onChange: (value: string) => void;
  length?: number;
  disabled?: boolean;
  className?: string;
  autoFocus?: boolean;
}

const PinCodeInput = forwardRef<PinCodeInputRef, Readonly<Props>>(function PinCodeInput(
  { value, onChange, length = 6, disabled = false, className, autoFocus = false },
  ref,
) {
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  useImperativeHandle(ref, () => ({
    focus: () => {
      inputRefs.current[0]?.focus();
    },
  }));

  const digits = value.split("").concat(new Array(length).fill("")).slice(0, length);
  const slotIds = Array.from({ length }, (_, i) => `pin-${i}`);

  const handleChange = (index: number, digit: string) => {
    if (!/^\d*$/.test(digit)) return;

    const newDigits = [...digits];
    newDigits[index] = digit.slice(-1);
    const newValue = newDigits.join("").replaceAll(/\s/g, "");
    onChange(newValue);

    if (digit && index < length - 1) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !digits[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
    if (e.key === "ArrowLeft" && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
    if (e.key === "ArrowRight" && index < length - 1) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData("text").replaceAll(/\D/g, "").slice(0, length);
    onChange(pastedData);

    const nextIndex = Math.min(pastedData.length, length - 1);
    inputRefs.current[nextIndex]?.focus();
  };

  const handleFocus = (e: React.FocusEvent<HTMLInputElement>) => {
    e.target.select();
  };

  return (
    <div className={cn("flex gap-2 w-full min-w-0", className)}>
      {digits.map((digit, index) => (
        <input
          key={slotIds[index]}
          id={slotIds[index]}
          ref={(el) => {
            inputRefs.current[index] = el;
          }}
          type="text"
          inputMode="numeric"
          maxLength={1}
          value={digit}
          onChange={(e) => handleChange(index, e.target.value)}
          onKeyDown={(e) => handleKeyDown(index, e)}
          onPaste={handlePaste}
          onFocus={handleFocus}
          disabled={disabled}
          autoFocus={autoFocus && index === 0}
          className={cn(
            "flex-1 min-w-0 h-[42px] text-center text-sm rounded-md",
            "dark:bg-nb-gray-900 border dark:border-nb-gray-700",
            "dark:placeholder:text-neutral-400/70",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2",
            "ring-offset-neutral-200/20 dark:ring-offset-neutral-950/50 dark:focus-visible:ring-neutral-500/20",
            "disabled:cursor-not-allowed disabled:opacity-40"
          )}
        />
      ))}
    </div>
  );
});

export default PinCodeInput;
